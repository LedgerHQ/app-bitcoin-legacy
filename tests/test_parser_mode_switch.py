"""Non-regression tests for Cerberus V-037 (lib-app-bitcoin).

The parser keeps its state in `context` but took its security mode as a
per-call argument. While reading a legacy input, `transaction.c` turns the
authorization hash off so the input script is excluded, and turns it back on
only when the call is in PARSE_MODE_SIGNATURE.

Ending the APDU right after the script-length byte returned early with the
switch still off. Resuming through GET TRUSTED INPUT P1_NEXT re-entered the
parser in trusted-input mode, so the restore never ran and later inputs stayed
out of the authorization hash - the value that binds later signing passes to
the approved transaction. Applied in both passes, an input could then be
swapped between them unnoticed.

The parse mode is now pinned for the life of a transaction, so the switch is
refused outright. Refusal reaches LEDGER_ASSERT and ends the app, so it is
observed the same way as the trusted-input checks.

TestParserModeSwitchVulnerable is the pre-fix behaviour, kept skipped so the
finding stays reproducible on an unfixed build.
"""
import struct
from pathlib import Path

import pytest

from ledger_bitcoin.btchip.bitcoinTransaction import bitcoinTransaction
from ledger_bitcoin.psbt import PSBT

from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware
from ragger.navigator import Navigator

from ragger_bitcoin import RaggerClient
from ragger_bitcoin.ragger_instructions import Instructions

from test_trusted_input_key import wait_until_refused

tests_root: Path = Path(__file__).parent

CLA = 0xE0
INS_GET_TRUSTED_INPUT = 0x42
INS_HASH_INPUT_START = 0x44
INS_HASH_INPUT_FINALIZE_FULL = 0x4A

P1_FIRST, P1_NEXT = 0x00, 0x80
P2_NEW, P2_CONTINUE = 0x00, 0x80
FINALIZE_P1_LAST = 0x80

SW_CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985

TRUSTED_INPUT_TOTAL_SIZE = 56
DEFAULT_SEQUENCE = b"\xff\xff\xff\xff"

RECIPIENT_P2PKH = bytes.fromhex(
    "76a914cbae5b50cf939e6f531b8a6b7abd788fe14b029788ac")


def prevout_of(psbt_name: str):
    psbt = PSBT()
    psbt.deserialize(open(f"{tests_root}/psbt/singlesig/{psbt_name}", "r").read())
    prevtx = bitcoinTransaction(psbt.inputs[0].non_witness_utxo.serialize())
    return prevtx, psbt.tx.vin[0].prevout.n, psbt.tx.nVersion


def apdu(ins, p1, p2, data: bytes) -> bytes:
    return bytes([CLA, ins, p1, p2, len(data)]) + data


def input_chunk(token: bytes) -> bytes:
    """Trusted input plus a zero script length, and nothing after it.

    The parser reads the length varint, finds no data left, and returns with
    the authorization hash still disabled.
    """
    return bytes([0x01, TRUSTED_INPUT_TOTAL_SIZE]) + token + b"\x00"


def outputs_blob(amount: int) -> bytes:
    return (b"\x01" + struct.pack("<Q", amount)
            + bytes([len(RECIPIENT_P2PKH)]) + RECIPIENT_P2PKH)


def status_of(backend, a: bytes) -> int:
    try:
        return backend.exchange_raw(a).status
    except ExceptionRAPDU as e:
        return e.status


def review_one_output(model: Firmware) -> Instructions:
    instructions = Instructions(model)
    if model.name.startswith("nano"):
        instructions.new_request("Accept")   # the output
        instructions.same_request("Accept")  # fees, "Accept and send"
    else:
        instructions.review_start(output_count=1)
        instructions.review_fees()
        instructions.confirm_transaction()
    return instructions


def start_pass(backend, version: int, first: bool) -> int:
    p2 = P2_NEW if first else P2_CONTINUE
    backend.exchange_raw(apdu(INS_HASH_INPUT_START, P1_FIRST, p2,
                              struct.pack("<I", version) + b"\x02"))
    return p2


def run_pass(client, version: int, tokens, first: bool, steal: bool,
             navigator=None, firmware=None, test_name="") -> int:
    """Streams one signing pass over two inputs; returns the finalize status.

    The first pass goes asynchronous into the output review and has to be
    approved: that approval clears `firstSigned`, which is what puts a second
    pass on the authorization-hash comparison branch.
    """
    backend = client.app.dongle.transport_client
    p2 = start_pass(backend, version, first)

    backend.exchange_raw(apdu(INS_HASH_INPUT_START, P1_NEXT, p2,
                              input_chunk(tokens[0])))
    ins = INS_GET_TRUSTED_INPUT if steal else INS_HASH_INPUT_START
    backend.exchange_raw(apdu(ins, P1_NEXT, 0x00 if steal else p2,
                              DEFAULT_SEQUENCE))

    backend.exchange_raw(apdu(INS_HASH_INPUT_START, P1_NEXT, p2,
                              input_chunk(tokens[1])))
    backend.exchange_raw(apdu(INS_HASH_INPUT_START, P1_NEXT, p2,
                              DEFAULT_SEQUENCE))

    final = apdu(INS_HASH_INPUT_FINALIZE_FULL, FINALIZE_P1_LAST, 0x00,
                 outputs_blob(500000))
    if first:
        instructions = review_one_output(firmware)
        client.app.dongle.set_navigation(True, navigator, test_name, instructions)
        client.app.dongle.exchange(bytearray(final))
        client.app.dongle.set_navigation(False, navigator, test_name, instructions)
        return client.app.dongle.last_async_response().status
    return status_of(backend, final)


class TestParserModeSwitch:

    def test_control_two_honest_passes_are_accepted(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        """The legal two-pass flow must still work.

        Catches a fix that pins the mode so tightly it bans normal signing.
        """
        prevtx, index, version = prevout_of("pkh-1to1.psbt")
        token_a = bytes(client.app.getTrustedInput(prevtx, index)["value"])
        token_b = bytes(client.app.getTrustedInput(prevtx, index)["value"])

        run_pass(client, version, [token_a, token_b], first=True, steal=False,
                 navigator=navigator, firmware=firmware, test_name=test_name)
        status = run_pass(client, version, [token_a, token_b],
                          first=False, steal=False)

        assert status != SW_CONDITIONS_OF_USE_NOT_SATISFIED, (
            f"got 0x{status:04X} on an honest replay; the fix broke normal "
            f"two-pass signing"
        )

    def test_mode_switch_is_refused(self, client: RaggerClient):
        """Resuming a signing parse in trusted-input mode must be refused.

        Observed on the switching APDU itself rather than a later finalize:
        finalize answers 0x6985 both for a hash mismatch and for a transaction
        that never reached PRESIGN_READY, so it cannot tell the two apart.
        Last in its class, since refusal exits the app.
        """
        prevtx, index, version = prevout_of("pkh-1to1.psbt")
        backend = client.app.dongle.transport_client

        token = bytes(client.app.getTrustedInput(prevtx, index)["value"])
        p2 = start_pass(backend, version, first=True)
        backend.exchange_raw(apdu(INS_HASH_INPUT_START, P1_NEXT, p2,
                                  input_chunk(token)))

        # The parse is mid-input. Resuming it in trusted-input mode is the
        # switch the fix pins against, and it never answers.
        backend.send_raw(apdu(INS_GET_TRUSTED_INPUT, P1_NEXT, 0x00,
                              DEFAULT_SEQUENCE))
        wait_until_refused(backend)


@pytest.mark.skip(reason="V-037 pre-fix behaviour; unskip on an unfixed build")
class TestParserModeSwitchVulnerable:
    """What the finding looked like. This passed before the fix."""

    def test_mode_switch_hides_a_swapped_input(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        prevtx, index, version = prevout_of("pkh-1to1.psbt")

        token_a = bytes(client.app.getTrustedInput(prevtx, index)["value"])
        token_b = bytes(client.app.getTrustedInput(prevtx, index)["value"])
        assert token_a != token_b

        run_pass(client, version, [token_a, token_b], first=True, steal=True,
                 navigator=navigator, firmware=firmware, test_name=test_name)

        token_c = bytes(client.app.getTrustedInput(prevtx, index)["value"])
        status = run_pass(client, version, [token_a, token_c],
                          first=False, steal=True)

        assert status != SW_CONDITIONS_OF_USE_NOT_SATISFIED
