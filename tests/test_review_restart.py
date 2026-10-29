"""Non-regression tests for Cerberus V-047 (lib-app-bitcoin).

Starting a transaction (HASH INPUT START with P1 first) restarts the signing
hashes, but used to leave the output review where the previous transaction
stopped: its unparsed bytes, its output count and its running subtotal. A new
transaction's outputs were then parsed as the tail of the old one, so what the
screen showed and what got signed could come from two different transactions.

Here transaction A declares two outputs and only the first is reviewed. Then
transaction B starts and sends its own complete output list. B must be reviewed
from its first byte. Before the fix, the parser was still waiting for A's second
output and read B's output count as part of an amount, which misaligned the rest
and was refused with 0x6F0F.

TestReviewRestartVulnerable is the pre-fix behaviour, kept skipped so the
finding stays reproducible on an unfixed build.
"""
import pytest

from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID

from ragger_bitcoin import RaggerClient
from ragger_bitcoin.ragger_instructions import Instructions

from test_op_return_omni import (CLA, INS_HASH_INPUT_FINALIZE_FULL,
                                 SW_TECHNICAL_PROBLEM_2, drive_to_outputs,
                                 payment_output)

FINALIZE_P1_MORE, FINALIZE_P1_LAST = 0x00, 0x80

SW_OK = 0x9000


def finalize(p1: int, outputs: bytes) -> bytes:
    return bytes([CLA, INS_HASH_INPUT_FINALIZE_FULL, p1, 0x00,
                  len(outputs)]) + outputs


def start_transaction(client: RaggerClient) -> None:
    """Streams the inputs of a one-input transaction, P1 first and P2 new."""
    drive_to_outputs(client, b"")


def review_first_output(model: Firmware) -> Instructions:
    instructions = Instructions(model)
    if model.name.startswith("nano"):
        instructions.new_request("Accept")
    else:
        instructions.review_start(output_count=1)
    return instructions


def review_whole_transaction(model: Firmware) -> Instructions:
    """One output, then fees. No HASH SIGN follows, so no status screen."""
    instructions = Instructions(model)
    if model.name.startswith("nano"):
        instructions.new_request("Accept")   # the payment
        instructions.same_request("Accept")  # fees, "Accept and send"
    else:
        instructions.review_start(output_count=1)
        instructions.review_fees()
        instructions.same_request("Sign", NavInsID.USE_CASE_REVIEW_TAP,
                                  NavInsID.USE_CASE_REVIEW_CONFIRM)
    return instructions


def navigated_status(client: RaggerClient, navigator: Navigator,
                     name: str, instructions: Instructions,
                     apdu: bytes) -> int:
    client.app.dongle.set_navigation(True, navigator, name, instructions)
    try:
        client.app.dongle.exchange(bytearray(apdu))
        status = client.app.dongle.last_async_response().status
    except ExceptionRAPDU as e:
        status = e.status
    client.app.dongle.set_navigation(False, navigator, name, instructions)
    return status


def leave_review_unfinished(client: RaggerClient, navigator: Navigator,
                            firmware: Firmware, test_name: str) -> None:
    """Transaction A: two outputs declared, one sent and approved."""
    start_transaction(client)
    status = navigated_status(
        client, navigator, f"{test_name}_a", review_first_output(firmware),
        finalize(FINALIZE_P1_MORE, b"\x02" + payment_output(500)))
    assert status == SW_OK, f"got 0x{status:04X}"


class TestReviewRestart:

    def test_new_transaction_is_reviewed_from_scratch(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        leave_review_unfinished(client, navigator, firmware, test_name)

        start_transaction(client)
        status = navigated_status(
            client, navigator, f"{test_name}_b",
            review_whole_transaction(firmware),
            finalize(FINALIZE_P1_LAST, b"\x01" + payment_output(500)))
        assert status == SW_OK, f"got 0x{status:04X}"


@pytest.mark.skip(reason="V-047 pre-fix behaviour; unskip on an unfixed build")
class TestReviewRestartVulnerable:
    """What the finding looked like. This passed before the fix."""

    def test_new_transaction_is_parsed_as_the_old_one(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        leave_review_unfinished(client, navigator, firmware, test_name)

        start_transaction(client)
        backend = client.app.dongle.transport_client
        try:
            status = backend.exchange_raw(
                finalize(FINALIZE_P1_LAST, b"\x01" + payment_output(500))).status
        except ExceptionRAPDU as e:
            status = e.status
        assert status == SW_TECHNICAL_PROBLEM_2, f"got 0x{status:04X}"
