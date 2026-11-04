"""Non-regression tests for lib-app-bitcoin-dev#30.

CHANGEINFO names the change path. An unusual path opens a warning, but the
change was registered before the warning opened, and a rejection only answered
0x6985. A host could ignore that and send the outputs: the one paying the
rejected path was then hidden as change, so the user approved a review that
never showed where that money went. A rejection now drops the change and ends
the transaction.

On Stax, Flex and Apex the warning was not even drawn once a review had opened
in the same transaction, for instance after the "Unverified inputs" warning:
the device rejected it on the user's behalf and the host could carry on the
same way. The warning is now always drawn.

The registered change is visible without reading the screen: two outputs
paying it make the review refuse the second with SW_TECHNICAL_PROBLEM_2
(0x6F0F, "Multiple change output").

TestChangePathRejectVulnerable is the pre-fix behaviour, kept skipped so the
finding stays reproducible on an unfixed build.
"""
import pytest

from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID

from ragger_bitcoin import RaggerClient
from ragger_bitcoin.ragger_instructions import Instructions

from test_changeinfo_order import (UNUSUAL_CHANGE_PATH, change_info,
                                   change_output)
from test_interleaved_command import RawApdu
from test_op_return_omni import (DEFAULT_SEQUENCE, SW_TECHNICAL_PROBLEM_2,
                                 payment_output)
from test_review_restart import (FINALIZE_P1_LAST, finalize, navigated_status,
                                 start_transaction)
from test_segwit_input_warning import (P1_FIRST, P1_NEXT, P2_NEW_SEGWIT,
                                       answer_warning, header, input_start,
                                       raw_segwit_input, status_of)

SW_OK = 0x9000
SW_CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985


def answer_change_path(model: Firmware, accept: bool,
                       review_open: bool = False) -> Instructions:
    """Once a review is open, NBGL shows the warning without its intro."""
    instructions = Instructions(model)
    if model.name.startswith("nano"):
        instructions.new_request("Approve" if accept else "Reject")
    else:
        choice = (NavInsID.USE_CASE_CHOICE_CONFIRM if accept
                  else NavInsID.USE_CASE_CHOICE_REJECT)
        if review_open:
            instructions.new_request("Unusual", NavInsID.USE_CASE_REVIEW_TAP,
                                     choice)
        else:
            instructions.new_request("Review", NavInsID.SWIPE_CENTER_TO_LEFT,
                                     NavInsID.SWIPE_CENTER_TO_LEFT)
            instructions.same_request("Unusual", NavInsID.USE_CASE_REVIEW_TAP,
                                      choice)
    return instructions.no_snapshots()


def reject_change_path(client: RaggerClient, navigator: Navigator,
                       firmware: Firmware, test_name: str) -> None:
    start_transaction(client)
    status = navigated_status(client, navigator, test_name,
                              answer_change_path(firmware, False),
                              change_info(UNUSUAL_CHANGE_PATH))
    assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, f"got 0x{status:04X}"


def two_rejected_change_outputs(client: RaggerClient) -> bytes:
    return (b"\x02"
            + change_output(client, UNUSUAL_CHANGE_PATH, 100000)
            + change_output(client, UNUSUAL_CHANGE_PATH, 200000))


def accept_unverified_inputs(client: RaggerClient, navigator: Navigator,
                             firmware: Firmware, test_name: str) -> None:
    """A raw segwit input opens the review before any output is sent."""
    assert status_of(client, input_start(P1_FIRST, P2_NEW_SEGWIT,
                                          header(1))) == SW_OK
    status = navigated_status(
        client, navigator, f"{test_name}_inputs",
        answer_warning(firmware, True),
        input_start(P1_NEXT, P2_NEW_SEGWIT, raw_segwit_input(0, 1000000)))
    assert status == SW_OK, f"got 0x{status:04X}"
    status = status_of(client, input_start(P1_NEXT, P2_NEW_SEGWIT,
                                           DEFAULT_SEQUENCE))
    assert status == SW_OK, f"got 0x{status:04X}"


class TestChangePathReject:

    def test_rejected_change_path_ends_the_transaction(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        outputs = two_rejected_change_outputs(client)
        reject_change_path(client, navigator, firmware, test_name)

        status = status_of(client, finalize(FINALIZE_P1_LAST, outputs))
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, (
            f"got 0x{status:04X}; 0x{SW_TECHNICAL_PROBLEM_2:04X} means the "
            "rejected change path still hides outputs")

    def test_payment_after_rejected_change_path_is_refused(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        """The refusal comes before any review, so the reply is immediate."""
        outputs = (b"\x02" + payment_output(1000)
                   + change_output(client, UNUSUAL_CHANGE_PATH, 900000))
        reject_change_path(client, navigator, firmware, test_name)

        # An unfixed build opens the review instead, and the read times out.
        raw = RawApdu(client.app.dongle.transport_client)
        raw.send(finalize(FINALIZE_P1_LAST, outputs))
        status = raw.status()
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, \
            f"got 0x{status:04X}"

    def test_change_path_warning_is_drawn_once_a_review_is_open(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        """Only a drawn warning can be approved; NBGL used to reject it unseen."""
        accept_unverified_inputs(client, navigator, firmware, test_name)

        status = navigated_status(
            client, navigator, test_name,
            answer_change_path(firmware, True, review_open=True),
            change_info(UNUSUAL_CHANGE_PATH))
        assert status == SW_OK, f"got 0x{status:04X}"


@pytest.mark.skip(reason="#30 pre-fix behaviour; unskip on an unfixed build")
class TestChangePathRejectVulnerable:
    """What the finding looked like. This passed before the fix."""

    def test_rejected_change_path_still_hides_outputs(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        outputs = two_rejected_change_outputs(client)
        reject_change_path(client, navigator, firmware, test_name)

        status = status_of(client, finalize(FINALIZE_P1_LAST, outputs))
        assert status == SW_TECHNICAL_PROBLEM_2, f"got 0x{status:04X}"

    def test_nbgl_rejects_the_warning_unseen(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        if firmware.name.startswith("nano"):
            pytest.skip("BAGL always drew the warning")
        accept_unverified_inputs(client, navigator, firmware, test_name)

        status = status_of(client, change_info(UNUSUAL_CHANGE_PATH))
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, \
            f"got 0x{status:04X}"
