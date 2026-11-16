"""Non-regression tests for Cerberus V-048 (lib-app-bitcoin), Hydra builds only.

Change detection compared the 20 bytes at the P2PKH hash offset of any output
that was neither P2SH nor native SegWit. On Bitcoin that is always P2PKH, but
Hydra also accepts OP_CALL and OP_CREATE contract outputs, so a contract output
carrying the change hash160 at that offset was hidden from review as change
while its amount still went into the fee total.

The script built here only has the shape the device checks: version, the
change hash where a P2PKH hash would sit, then OP_CALL. A wallet can grind its
standard change index until the hash also parses as valid OP_CALL fields.

As for V-004, two such outputs make the classification visible without reading
the screen: `check_output_displayable()` refuses a second change output, so an
unfixed build answers SW_TECHNICAL_PROBLEM_2 (0x6F0F).

TestHydraContractChangeVulnerable is the pre-fix behaviour, kept skipped so the
finding stays reproducible on an unfixed build.

Build with COIN=hydra_testnet (or hydra) and run this file alone: the rest of
the suite targets the Bitcoin testnet build, and this one skips there.
"""
import struct

import pytest

from ledger_bitcoin.btchip.btchipHelpers import parse_bip32_path
from ledger_bitcoin.common import hash160

from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware
from ragger.navigator import Navigator

from ragger_bitcoin import RaggerClient

from test_p2wsh_change import compressed_pubkey, prevout_of, review_two_outputs

CLA = 0xE0
INS_GET_COIN_VER = 0x16
INS_HASH_INPUT_START = 0x44
INS_HASH_INPUT_FINALIZE_FULL = 0x4A

FINALIZE_P1_LAST = 0x80
FINALIZE_P1_CHANGEINFO = 0xFF

SW_TECHNICAL_PROBLEM_2 = 0x6F0F

TRUSTED_INPUT_TOTAL_SIZE = 56
DEFAULT_SEQUENCE = b"\xff\xff\xff\xff"

# Hydra builds set BIP44_COIN_TYPE=0, so any coin type is canonical and this
# path raises no warning.
CHANGE_PATH = "44'/609'/0'/1/0"

OP_4 = 0x54
OP_CALL = 0xC2


@pytest.fixture(autouse=True)
def hydra_only(client: RaggerClient):
    reply = client.app.dongle.transport_client.exchange_raw(
        bytes([CLA, INS_GET_COIN_VER, 0x00, 0x00, 0x00])).data
    coin_id = reply[6:6 + reply[5]]
    if coin_id != b"Hydra":
        pytest.skip(f"needs a Hydra build, this one is {coin_id.decode()}")


def op_call_output(change_h160: bytes, amount: int) -> bytes:
    """An OP_CALL output whose bytes at the P2PKH hash offset are the change."""
    script = bytes([OP_4, 0x02, 0x00]) + change_h160 + bytes([OP_CALL])
    return struct.pack("<Q", amount) + bytes([len(script)]) + script


def p2pkh_output(h160: bytes, amount: int) -> bytes:
    script = b"\x76\xa9\x14" + h160 + b"\x88\xac"
    return struct.pack("<Q", amount) + bytes([len(script)]) + script


def drive_to_outputs(client: RaggerClient, make_output) -> bytes:
    """Streams everything up to the output APDU and returns that APDU."""
    prevtx, index, version = prevout_of("pkh-1to1.psbt")
    backend = client.app.dongle.transport_client

    # Take the change hash from the device, so the test cannot pass by
    # agreeing with itself about the seed.
    pub = client.app.getWalletPublicKey(CHANGE_PATH)["publicKey"]
    change_h160 = hash160(compressed_pubkey(bytes(pub)))
    assert len(change_h160) == 20

    token = bytes(client.app.getTrustedInput(prevtx, index)["value"])
    assert len(token) == TRUSTED_INPUT_TOTAL_SIZE

    header = struct.pack("<I", version) + b"\x01"
    backend.exchange_raw(
        bytes([CLA, INS_HASH_INPUT_START, 0x00, 0x00, len(header)]) + header)
    payload = bytes([0x01, TRUSTED_INPUT_TOTAL_SIZE]) + token + b"\x00"
    backend.exchange_raw(
        bytes([CLA, INS_HASH_INPUT_START, 0x80, 0x00, len(payload)]) + payload)
    backend.exchange_raw(
        bytes([CLA, INS_HASH_INPUT_START, 0x80, 0x00, 4]) + DEFAULT_SEQUENCE)

    path = bytes(parse_bip32_path(CHANGE_PATH))
    backend.exchange_raw(
        bytes([CLA, INS_HASH_INPUT_FINALIZE_FULL, FINALIZE_P1_CHANGEINFO, 0x00,
               len(path)]) + path)

    outputs = (b"\x02"
               + make_output(change_h160, 100000)
               + make_output(change_h160, 200000))
    return bytes([CLA, INS_HASH_INPUT_FINALIZE_FULL, FINALIZE_P1_LAST, 0x00,
                  len(outputs)]) + outputs


def status_of(client: RaggerClient, apdu: bytes) -> int:
    try:
        return client.app.dongle.transport_client.exchange_raw(apdu).status
    except ExceptionRAPDU as e:
        return e.status


class TestHydraContractChange:

    def test_p2pkh_change_is_still_detected(self, client: RaggerClient):
        """Control: two real P2PKH change outputs are both recognised as change."""
        apdu = drive_to_outputs(client, p2pkh_output)
        status = status_of(client, apdu)
        assert status == SW_TECHNICAL_PROBLEM_2, (
            f"expected 0x{SW_TECHNICAL_PROBLEM_2:04X} (multiple change output), "
            f"got 0x{status:04X}: P2PKH change is no longer detected"
        )

    def test_op_call_is_not_treated_as_change(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        """Both OP_CALL outputs must reach the user instead of being hidden."""
        apdu = drive_to_outputs(client, op_call_output)

        instructions = review_two_outputs(firmware)
        client.app.dongle.set_navigation(True, navigator, test_name, instructions)
        client.app.dongle.exchange(bytearray(apdu))
        client.app.dongle.set_navigation(False, navigator, test_name, instructions)

        status = client.app.dongle.last_async_response().status
        assert status != SW_TECHNICAL_PROBLEM_2, (
            "device reported multiple change outputs, so it still classifies "
            "an OP_CALL output as change"
        )


@pytest.mark.skip(reason="V-048 pre-fix behaviour; unskip on an unfixed build")
class TestHydraContractChangeVulnerable:
    """What the finding looked like. This passed before the fix."""

    def test_op_call_is_misclassified_as_change(self, client: RaggerClient):
        apdu = drive_to_outputs(client, op_call_output)
        status = status_of(client, apdu)
        assert status == SW_TECHNICAL_PROBLEM_2, (
            f"expected 0x{SW_TECHNICAL_PROBLEM_2:04X} (multiple change output), "
            f"got 0x{status:04X}"
        )
