"""Non-regression tests for Cerberus V-004 (lib-app-bitcoin).

Change detection compared 20 bytes at the witness-program offset while the
recogniser accepted both P2WPKH (20-byte program) and P2WSH (32-byte program).
A P2WSH program shaped as `change_hash160 || junk[12]` therefore matched, and
the output was hidden from review while still counted in the total. Nobody
holds a witness script for it, so the amount was burned silently.

Two P2WSH outputs make the classification observable without reading the
screen: `check_output_displayable()` refuses a second change output, so on an
unfixed build the device answers SW_TECHNICAL_PROBLEM_2 (0x6F0F). Once neither
is change, both are displayed and the device asks the user instead.

TestP2wshChangeVulnerable is the pre-fix behaviour, kept skipped so the finding
stays reproducible on an unfixed build.
"""
import struct
from pathlib import Path

import pytest

from ledger_bitcoin.btchip.bitcoinTransaction import bitcoinTransaction
from ledger_bitcoin.btchip.btchipHelpers import parse_bip32_path
from ledger_bitcoin.common import hash160
from ledger_bitcoin.psbt import PSBT

from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware
from ragger.navigator import Navigator

from ragger_bitcoin import RaggerClient
from ragger_bitcoin.ragger_instructions import Instructions

tests_root: Path = Path(__file__).parent

CLA = 0xE0
INS_HASH_INPUT_START = 0x44
INS_HASH_INPUT_FINALIZE_FULL = 0x4A

FINALIZE_P1_LAST = 0x80
FINALIZE_P1_CHANGEINFO = 0xFF

SW_TECHNICAL_PROBLEM_2 = 0x6F0F

TRUSTED_INPUT_TOTAL_SIZE = 56
DEFAULT_SEQUENCE = b"\xff\xff\xff\xff"

# Canonical BIP44 change path for the testnet build, so the device does not
# divert into its non-canonical-path warning.
CHANGE_PATH = "44'/1'/0'/1/0"


def compressed_pubkey(uncompressed: bytes) -> bytes:
    """65-byte 04||X||Y to 33-byte 02/03||X, which is what the device hashes."""
    assert len(uncompressed) == 65 and uncompressed[0] == 0x04
    prefix = 0x03 if uncompressed[64] & 1 else 0x02
    return bytes([prefix]) + uncompressed[1:33]


def pseudo_change_output(change_h160: bytes, filler: int, amount: int) -> bytes:
    """A P2WSH output whose first 20 program bytes are the change hash160."""
    program = change_h160 + bytes([filler]) * 12
    script = b"\x00\x20" + program                # witness v0, 32-byte program
    return struct.pack("<Q", amount) + bytes([len(script)]) + script


def prevout_of(psbt_name: str):
    psbt = PSBT()
    psbt.deserialize(open(f"{tests_root}/psbt/singlesig/{psbt_name}", "r").read())
    prevtx = bitcoinTransaction(psbt.inputs[0].non_witness_utxo.serialize())
    return prevtx, psbt.tx.vin[0].prevout.n, psbt.tx.nVersion


def review_two_outputs(model: Firmware) -> Instructions:
    """Both outputs get their own approval round, then the finalize flow."""
    instructions = Instructions(model)
    if model.name.startswith("nano"):
        instructions.new_request("Accept")   # output 1
        instructions.same_request("Accept")  # output 2
        instructions.same_request("Accept")  # fees, "Accept and send"
    else:
        instructions.review_start(output_count=2)
        instructions.review_fees()
        instructions.confirm_transaction()
    return instructions


def drive_to_outputs(client: RaggerClient, change_h160_out: list) -> bytes:
    """Streams everything up to the output APDU and returns that APDU."""
    prevtx, index, version = prevout_of("pkh-1to1.psbt")
    backend = client.app.dongle.transport_client

    # Take the change hash from the device, so the test cannot pass by
    # agreeing with itself about the seed.
    pub = client.app.getWalletPublicKey(CHANGE_PATH)["publicKey"]
    change_h160 = hash160(compressed_pubkey(bytes(pub)))
    assert len(change_h160) == 20
    change_h160_out.append(change_h160)

    token = bytes(client.app.getTrustedInput(prevtx, index)["value"])
    assert len(token) == TRUSTED_INPUT_TOTAL_SIZE

    header = struct.pack("<I", version) + b"\x01"
    backend.exchange_raw(
        bytes([CLA, INS_HASH_INPUT_START, 0x00, 0x00, len(header)]) + header)
    payload = bytes([0x01, TRUSTED_INPUT_TOTAL_SIZE]) + token + b"\x00"
    backend.exchange_raw(
        bytes([CLA, INS_HASH_INPUT_START, 0x80, 0x00, len(payload)]) + payload)
    # An input is only complete once its sequence arrives; until then the
    # parser never reaches TRANSACTION_PRESIGN_READY.
    backend.exchange_raw(
        bytes([CLA, INS_HASH_INPUT_START, 0x80, 0x00, 4]) + DEFAULT_SEQUENCE)

    path = bytes(parse_bip32_path(CHANGE_PATH))
    backend.exchange_raw(
        bytes([CLA, INS_HASH_INPUT_FINALIZE_FULL, FINALIZE_P1_CHANGEINFO, 0x00,
               len(path)]) + path)

    outputs = (b"\x02"
               + pseudo_change_output(change_h160, 0xAA, 100000)
               + pseudo_change_output(change_h160, 0xBB, 200000))
    return bytes([CLA, INS_HASH_INPUT_FINALIZE_FULL, FINALIZE_P1_LAST, 0x00,
                  len(outputs)]) + outputs


class TestP2wshChange:

    def test_p2wsh_is_not_treated_as_change(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        """Both P2WSH outputs must reach the user instead of being hidden."""
        change = []
        apdu = drive_to_outputs(client, change)

        instructions = review_two_outputs(firmware)
        client.app.dongle.set_navigation(True, navigator, test_name, instructions)
        client.app.dongle.exchange(bytearray(apdu))
        client.app.dongle.set_navigation(False, navigator, test_name, instructions)

        status = client.app.dongle.last_async_response().status
        assert status != SW_TECHNICAL_PROBLEM_2, (
            "device reported multiple change outputs, so it still classifies "
            "a P2WSH program as change"
        )


@pytest.mark.skip(reason="V-004 pre-fix behaviour; unskip on an unfixed build")
class TestP2wshChangeVulnerable:
    """What the finding looked like. This passed before the fix."""

    def test_p2wsh_is_misclassified_as_change(self, client: RaggerClient):
        change = []
        apdu = drive_to_outputs(client, change)
        backend = client.app.dongle.transport_client

        try:
            status = backend.exchange_raw(apdu).status
        except ExceptionRAPDU as e:
            status = e.status

        assert status == SW_TECHNICAL_PROBLEM_2, (
            f"expected 0x{SW_TECHNICAL_PROBLEM_2:04X} (multiple change output), "
            f"got 0x{status:04X}"
        )
