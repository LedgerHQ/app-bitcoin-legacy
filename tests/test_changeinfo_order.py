"""Non-regression tests for Cerberus V-054 (lib-app-bitcoin).

CHANGEINFO names the change path, and wallets send it before the outputs. The
device accepted it at any point of the output stream, though, and an unusual
path made it open a warning and then reset the output review to "read the
output count", while the hashes kept everything already sent. A host could
send the count, then CHANGEINFO, then outputs crafted so the review read a
second count out of them: the screen and the signature then framed the same
bytes as different outputs.

CHANGEINFO is now refused once output bytes have been sent.

The re-framing is visible without reading the screen. After the count 02, the
bytes `02 || change || change` start an output in the hashed framing, whose
script length (the change amount's top byte) runs past the chunk, so the review
ends with SW_INCORRECT_DATA (0x6A80). Only a review that read 02 as a new count
sees two change outputs, and refuses the second with SW_TECHNICAL_PROBLEM_2
(0x6F0F).

TestChangeinfoOrderVulnerable is the pre-fix behaviour, kept skipped so the
finding stays reproducible on an unfixed build.
"""
import struct

import pytest

from ledger_bitcoin.btchip.btchipHelpers import parse_bip32_path
from ledger_bitcoin.common import hash160

from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID

from ragger_bitcoin import RaggerClient
from ragger_bitcoin.ragger_instructions import Instructions

from test_interleaved_command import RawApdu
from test_op_return_omni import (CLA, INS_HASH_INPUT_FINALIZE_FULL,
                                 SW_TECHNICAL_PROBLEM_2, payment_output)
from test_p2wsh_change import compressed_pubkey
from test_review_restart import (FINALIZE_P1_LAST, FINALIZE_P1_MORE, finalize,
                                 navigated_status, start_transaction)
from test_segwit_input_warning import status_of

FINALIZE_P1_CHANGEINFO = 0xFF

SW_OK = 0x9000
SW_CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985

# An address index above 50000 makes the device warn about the change path.
UNUSUAL_CHANGE_PATH = "44'/1'/0'/1/50001"

# The top amount byte is the script length in the hashed framing: 0x40 bytes
# run past the 69-byte chunk.
LARGE_AMOUNT = 0x40 << 56


def change_info(path: str) -> bytes:
    data = bytes(parse_bip32_path(path))
    return bytes([CLA, INS_HASH_INPUT_FINALIZE_FULL, FINALIZE_P1_CHANGEINFO,
                  0x00, len(data)]) + data


def change_output(client: RaggerClient, path: str, amount: int) -> bytes:
    """A P2PKH output paying the device's own key at `path`."""
    pub = client.app.getWalletPublicKey(path)["publicKey"]
    h160 = hash160(compressed_pubkey(bytes(pub)))
    script = b"\x76\xa9\x14" + h160 + b"\x88\xac"
    return struct.pack("<Q", amount) + bytes([len(script)]) + script


def two_change_outputs(client: RaggerClient) -> bytes:
    return (b"\x02"
            + change_output(client, UNUSUAL_CHANGE_PATH, LARGE_AMOUNT)
            + change_output(client, UNUSUAL_CHANGE_PATH, 100000))


def approve_change_path(model: Firmware) -> Instructions:
    instructions = Instructions(model)
    if model.name.startswith("nano"):
        instructions.new_request("Approve")
    else:
        instructions.new_request("Review", NavInsID.SWIPE_CENTER_TO_LEFT,
                                 NavInsID.SWIPE_CENTER_TO_LEFT)
        instructions.same_request("Unusual", NavInsID.USE_CASE_REVIEW_TAP,
                                  NavInsID.USE_CASE_CHOICE_CONFIRM)
    return instructions.no_snapshots()


class TestChangeinfoOrder:

    def test_control_changeinfo_before_outputs(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        """What wallets send: the warning, then outputs framed from the count."""
        outputs = two_change_outputs(client)
        start_transaction(client)
        status = navigated_status(client, navigator, test_name,
                                  approve_change_path(firmware),
                                  change_info(UNUSUAL_CHANGE_PATH))
        assert status == SW_OK, f"got 0x{status:04X}"
        status = status_of(client, finalize(FINALIZE_P1_LAST, outputs))
        assert status == SW_TECHNICAL_PROBLEM_2, (
            f"expected 0x{SW_TECHNICAL_PROBLEM_2:04X} (multiple change "
            f"output), got 0x{status:04X}: change is no longer detected")

    @pytest.mark.parametrize("sent", [
        pytest.param(b"\x02", id="count"),
        pytest.param(b"\xfd", id="partial_count"),
        pytest.param(b"\x02" + payment_output(500)[:10], id="partial_output"),
    ])
    def test_changeinfo_after_output_bytes_is_refused(
            self, client: RaggerClient, sent: bytes):
        """The refusal comes before any warning, so the reply is immediate."""
        start_transaction(client)
        assert status_of(client, finalize(FINALIZE_P1_MORE, sent)) == SW_OK

        # An unfixed build opens the warning instead, and the read times out.
        raw = RawApdu(client.app.dongle.transport_client)
        raw.send(change_info(UNUSUAL_CHANGE_PATH))
        status = raw.status()
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, \
            f"got 0x{status:04X}"


@pytest.mark.skip(reason="V-054 pre-fix behaviour; unskip on an unfixed build")
class TestChangeinfoOrderVulnerable:
    """What the finding looked like. This passed before the fix."""

    def test_changeinfo_after_count_reframes_outputs(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        outputs = two_change_outputs(client)
        start_transaction(client)
        assert status_of(client, finalize(FINALIZE_P1_MORE, b"\x02")) == SW_OK
        status = navigated_status(client, navigator, test_name,
                                  approve_change_path(firmware),
                                  change_info(UNUSUAL_CHANGE_PATH))
        assert status == SW_OK, f"got 0x{status:04X}"
        status = status_of(client, finalize(FINALIZE_P1_LAST, outputs))
        assert status == SW_TECHNICAL_PROBLEM_2, (
            f"expected 0x{SW_TECHNICAL_PROBLEM_2:04X} (count read twice), "
            f"got 0x{status:04X}")
