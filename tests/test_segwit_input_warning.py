"""Non-regression tests for Cerberus V-046 (lib-app-bitcoin).

A SegWit input sent raw (flag 0x02) rather than as a TrustedInput carries an
amount nothing vouches for, and that amount feeds the fee shown at review. The
"Unverified inputs" warning exists so the user knows that fee cannot be
trusted. It used to be triggered by the shape of the APDU, so a host that
packed the input differently got no warning at all. The warning now follows
what the parser read.

Rejecting the warning also used to answer 0x6985 and nothing more: a first pass
packed into one APDU was already parsed, so the host could carry on to the
review with the unverified amount. A rejection now ends the transaction, and
the review refuses an unverified amount the user did not accept.

While the warning is on screen the device holds its reply, so an immediate
0x9000 to an APDU carrying a raw input means no warning was shown. Each test
below rejects the warning, which only yields 0x6985 if it was displayed.

TestSegwitInputWarningVulnerable is the pre-fix behaviour, kept skipped so the
finding stays reproducible on an unfixed build.
"""
import struct

import pytest

from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID

from ragger_bitcoin import RaggerClient
from ragger_bitcoin.ragger_instructions import Instructions

from test_op_return_omni import (CLA, DEFAULT_SEQUENCE, INS_HASH_INPUT_START,
                                 payment_output)
from test_review_restart import (FINALIZE_P1_LAST, finalize, navigated_status,
                                 review_whole_transaction)

P1_FIRST, P1_NEXT = 0x00, 0x80
P2_NEW_SEGWIT, P2_CONTINUE = 0x02, 0x80

SW_OK = 0x9000
SW_CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985


def header(input_count: int) -> bytes:
    return struct.pack("<I", 2) + bytes([input_count])


def raw_segwit_input(index: int, amount: int) -> bytes:
    """Flag 0x02, prevout, amount, empty script: the host's word only."""
    prevout = bytes([index + 1]) * 32 + struct.pack("<I", index)
    return b"\x02" + prevout + struct.pack("<Q", amount) + b"\x00"


def input_start(p1: int, p2: int, data: bytes) -> bytes:
    return bytes([CLA, INS_HASH_INPUT_START, p1, p2, len(data)]) + data


def status_of(client: RaggerClient, apdu: bytes) -> int:
    try:
        return client.app.dongle.transport_client.exchange_raw(apdu).status
    except ExceptionRAPDU as e:
        return e.status


def answer_warning(model: Firmware, accept: bool) -> Instructions:
    instructions = Instructions(model)
    if model.name.startswith("nano"):
        instructions.new_request("Continue" if accept else "Cancel")
    else:
        instructions.new_request("Review", NavInsID.SWIPE_CENTER_TO_LEFT,
                                 NavInsID.SWIPE_CENTER_TO_LEFT)
        instructions.same_request(
            "Unverified", NavInsID.USE_CASE_REVIEW_TAP,
            NavInsID.USE_CASE_CHOICE_CONFIRM if accept
            else NavInsID.USE_CASE_CHOICE_REJECT)
    return instructions


def rejected_status(client: RaggerClient, navigator: Navigator,
                    firmware: Firmware, test_name: str, apdu: bytes) -> int:
    return navigated_status(client, navigator, test_name,
                            answer_warning(firmware, False), apdu)


def reject_complete_first_pass(client: RaggerClient, navigator: Navigator,
                               firmware: Firmware, test_name: str) -> None:
    """One APDU carries the whole first pass, so parsing is done on rejection."""
    status = rejected_status(
        client, navigator, firmware, test_name,
        input_start(P1_FIRST, P2_NEW_SEGWIT,
                    header(1) + raw_segwit_input(0, 1000) + DEFAULT_SEQUENCE))
    assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, f"got 0x{status:04X}"


REVIEW_OUTPUTS = finalize(FINALIZE_P1_LAST, b"\x01" + payment_output(500))


class TestSegwitInputWarning:

    def test_control_input_in_its_own_apdu_is_warned(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        """The shape every wallet sends: warned once, then the inputs go on."""
        assert status_of(client, input_start(P1_FIRST, P2_NEW_SEGWIT,
                                              header(1))) == SW_OK
        status = navigated_status(
            client, navigator, test_name, answer_warning(firmware, True),
            input_start(P1_NEXT, P2_NEW_SEGWIT, raw_segwit_input(0, 1000)))
        assert status == SW_OK, f"got 0x{status:04X}"
        status = status_of(client, input_start(P1_NEXT, P2_NEW_SEGWIT,
                                               DEFAULT_SEQUENCE))
        assert status == SW_OK, f"got 0x{status:04X}"

    def test_input_packed_into_first_apdu_is_warned(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        status = rejected_status(
            client, navigator, firmware, test_name,
            input_start(P1_FIRST, P2_NEW_SEGWIT,
                        header(1) + raw_segwit_input(0, 1000)
                        + DEFAULT_SEQUENCE))
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, \
            f"got 0x{status:04X}"

    def test_two_inputs_in_one_apdu_are_warned(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        assert status_of(client, input_start(P1_FIRST, P2_NEW_SEGWIT,
                                              header(2))) == SW_OK
        status = rejected_status(
            client, navigator, firmware, test_name,
            input_start(P1_NEXT, P2_NEW_SEGWIT,
                        raw_segwit_input(0, 1000) + DEFAULT_SEQUENCE
                        + raw_segwit_input(1, 1000) + DEFAULT_SEQUENCE))
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, \
            f"got 0x{status:04X}"

    def test_input_flagged_continue_is_warned(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        assert status_of(client, input_start(P1_FIRST, P2_NEW_SEGWIT,
                                              header(1))) == SW_OK
        status = rejected_status(
            client, navigator, firmware, test_name,
            input_start(P1_NEXT, P2_CONTINUE, raw_segwit_input(0, 1000)))
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, \
            f"got 0x{status:04X}"

    def test_review_after_rejected_warning_is_refused(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        reject_complete_first_pass(client, navigator, firmware, test_name)

        status = status_of(client, REVIEW_OUTPUTS)
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, \
            f"got 0x{status:04X}"

    def test_rejected_warning_ends_the_transaction(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        assert status_of(client, input_start(P1_FIRST, P2_NEW_SEGWIT,
                                              header(1))) == SW_OK
        status = rejected_status(
            client, navigator, firmware, test_name,
            input_start(P1_NEXT, P2_NEW_SEGWIT, raw_segwit_input(0, 1000)))
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, \
            f"got 0x{status:04X}"
        status = status_of(client, input_start(P1_NEXT, P2_NEW_SEGWIT,
                                               DEFAULT_SEQUENCE))
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, \
            f"got 0x{status:04X}"


@pytest.mark.skip(reason="V-046 pre-fix behaviour; unskip on an unfixed build")
class TestSegwitInputWarningVulnerable:
    """What the finding looked like. These passed before the fix."""

    def test_input_packed_into_first_apdu_is_not_warned(
            self, client: RaggerClient):
        status = status_of(client, input_start(
            P1_FIRST, P2_NEW_SEGWIT,
            header(1) + raw_segwit_input(0, 1000) + DEFAULT_SEQUENCE))
        assert status == SW_OK, f"got 0x{status:04X}"

    def test_two_inputs_in_one_apdu_are_not_warned(
            self, client: RaggerClient):
        assert status_of(client, input_start(P1_FIRST, P2_NEW_SEGWIT,
                                              header(2))) == SW_OK
        status = status_of(client, input_start(
            P1_NEXT, P2_NEW_SEGWIT,
            raw_segwit_input(0, 1000) + DEFAULT_SEQUENCE
            + raw_segwit_input(1, 1000) + DEFAULT_SEQUENCE))
        assert status == SW_OK, f"got 0x{status:04X}"

    def test_input_flagged_continue_is_not_warned(
            self, client: RaggerClient):
        assert status_of(client, input_start(P1_FIRST, P2_NEW_SEGWIT,
                                              header(1))) == SW_OK
        status = status_of(client, input_start(
            P1_NEXT, P2_CONTINUE, raw_segwit_input(0, 1000)))
        assert status == SW_OK, f"got 0x{status:04X}"

    def test_review_after_rejected_warning_is_approved(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        reject_complete_first_pass(client, navigator, firmware, test_name)

        status = navigated_status(client, navigator, test_name,
                                  review_whole_transaction(firmware),
                                  REVIEW_OUTPUTS)
        assert status == SW_OK, f"got 0x{status:04X}"
