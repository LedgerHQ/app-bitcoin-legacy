"""Non-regression tests for Cerberus V-044 and V-043 (lib-app-bitcoin).

The host declares an output count, then streams the outputs over FINALIZE
chunks, the final one flagged LAST. Every byte goes into the signed hash, and
the SegWit output hash is only closed by LAST. The review, though, finished as
soon as it had read the declared count, whatever came after and whichever chunk
it was:

- V-044: "1 output" followed by two outputs signed both and showed one. In
  SegWit the count is not part of hashOutputs, and the hidden one read as fee.
- V-043: a review finishing on a MORE chunk was approved before LAST closed the
  SegWit output hash, so signing used a hash left by an earlier transaction.

The review now finishes only on the LAST chunk, right at the end of the last
declared output; anything else is refused with 0x6A80.

TestOutputStreamEndVulnerable is the pre-fix behaviour, kept skipped so the
findings stay reproducible on an unfixed build.
"""
import pytest

from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware
from ragger.navigator import Navigator

from ragger_bitcoin import RaggerClient

from test_op_return_omni import drive_to_outputs, payment_output
from test_review_restart import (FINALIZE_P1_MORE, finalize, navigated_status,
                                 review_first_output, review_whole_transaction,
                                 start_transaction)

SW_OK = 0x9000
SW_INCORRECT_DATA = 0x6A80


def finalize_status(client: RaggerClient, outputs: bytes) -> int:
    apdu = drive_to_outputs(client, outputs)
    try:
        return client.app.dongle.transport_client.exchange_raw(apdu).status
    except ExceptionRAPDU as e:
        return e.status


class TestOutputStreamEnd:

    def test_control_declared_outputs_only(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        """An exact output list on LAST must still reach the fee screen.

        Catches a gate that refuses on the last output instead of only on
        what follows it.
        """
        apdu = drive_to_outputs(client, b"\x01" + payment_output(500))
        status = navigated_status(client, navigator, test_name,
                                  review_whole_transaction(firmware), apdu)
        assert status == SW_OK, f"got 0x{status:04X}"

    def test_output_after_last_reviewed_is_refused(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        """V-044: one output declared, two sent."""
        apdu = drive_to_outputs(
            client, b"\x01" + payment_output(500) + payment_output(400))
        status = navigated_status(client, navigator, test_name,
                                  review_first_output(firmware), apdu)
        assert status == SW_INCORRECT_DATA, f"got 0x{status:04X}"

    def test_output_after_zero_count_is_refused(self, client: RaggerClient):
        """V-044: no output declared, one sent, refused with nothing shown."""
        status = finalize_status(client, b"\x00" + payment_output(500))
        assert status == SW_INCORRECT_DATA, f"got 0x{status:04X}"

    def test_review_ending_on_more_is_refused(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        """V-043: every declared output sent in a MORE chunk."""
        start_transaction(client)
        status = navigated_status(
            client, navigator, test_name, review_first_output(firmware),
            finalize(FINALIZE_P1_MORE, b"\x01" + payment_output(500)))
        assert status == SW_INCORRECT_DATA, f"got 0x{status:04X}"

    def test_last_ending_mid_output_is_refused(self, client: RaggerClient):
        """LAST closes the hash, so it cannot leave an output half sent."""
        status = finalize_status(client, b"\x01" + payment_output(500)[:20])
        assert status == SW_INCORRECT_DATA, f"got 0x{status:04X}"


@pytest.mark.skip(reason="V-044/V-043 pre-fix behaviour; unskip on an unfixed build")
class TestOutputStreamEndVulnerable:
    """What the findings looked like. These passed before the fix."""

    def test_output_after_last_reviewed_is_signed(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        apdu = drive_to_outputs(
            client, b"\x01" + payment_output(500) + payment_output(400))
        status = navigated_status(client, navigator, test_name,
                                  review_whole_transaction(firmware), apdu)
        assert status == SW_OK

    def test_review_ending_on_more_is_approved(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        start_transaction(client)
        status = navigated_status(
            client, navigator, test_name, review_whole_transaction(firmware),
            finalize(FINALIZE_P1_MORE, b"\x01" + payment_output(500)))
        assert status == SW_OK
