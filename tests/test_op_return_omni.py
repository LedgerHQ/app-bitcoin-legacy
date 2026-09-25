"""Non-regression tests for Cerberus V-016 and V-038 (lib-app-bitcoin).

Omni rides on a zero-value OP_RETURN output. The library used to recognise one
byte-for-byte layout of it and render that; every other operation or push
encoding fell through to the generic branch, where the output shows as the word
`OP_RETURN` with a zero native amount while its payload is signed. Real value
moves in a field the screen treats as empty.

Omni is no longer rendered at all, so the payload is now refused instead. The
check walks the OP_RETURN push program rather than reading a fixed offset,
because the marker's position depends on the encoding: an earlier attempt that
matched at fixed offsets covered a direct push, OP_PUSHDATA1 and OP_PUSHDATA2,
and was bypassed by OP_PUSHDATA4, which is V-038.

`test_plain_op_return_is_accepted` is the one that stops this becoming a blunt
ban: Ledger Live attaches OP_RETURN data to Bitcoin transactions through the
Wallet API and through swap, so a non-Omni payload has to keep working.

TestOpReturnOmniVulnerable is the pre-fix behaviour, kept skipped so the finding
stays reproducible on an unfixed build.
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

tests_root: Path = Path(__file__).parent

CLA = 0xE0
INS_HASH_INPUT_START = 0x44
INS_HASH_INPUT_FINALIZE_FULL = 0x4A

FINALIZE_P1_LAST = 0x80

SW_TECHNICAL_PROBLEM_2 = 0x6F0F

TRUSTED_INPUT_TOTAL_SIZE = 56
DEFAULT_SEQUENCE = b"\xff\xff\xff\xff"

OP_RETURN = 0x6A
OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4 = 0x4C, 0x4D, 0x4E

RECIPIENT_P2PKH = bytes.fromhex(
    "76a914cbae5b50cf939e6f531b8a6b7abd788fe14b029788ac")

# Omni Class C Simple Send: marker, version+type, property id, amount.
OMNI_SIMPLE_SEND = (b"omni" + bytes(4) + struct.pack(">I", 31)
                    + struct.pack(">Q", 100_000_000))

# What Ledger Live actually sends: arbitrary bytes, no marker. Same payload as
# its own `Send with OP_RETURN` dataset test.
LEDGER_LIVE_PAYLOAD = b"charley loves heidi"


def pushed(payload: bytes, encoding: str) -> bytes:
    """The payload as a push program, in each encoding a wallet could use."""
    if encoding == "direct":
        assert len(payload) <= 0x4B
        return bytes([len(payload)]) + payload
    if encoding == "pushdata1":
        return bytes([OP_PUSHDATA1, len(payload)]) + payload
    if encoding == "pushdata2":
        return bytes([OP_PUSHDATA2]) + struct.pack("<H", len(payload)) + payload
    if encoding == "pushdata4":
        return bytes([OP_PUSHDATA4]) + struct.pack("<I", len(payload)) + payload
    if encoding == "split":
        # One push per byte. No single push opens with the marker, so only
        # concatenating the payload reveals it.
        return b"".join(bytes([1, b]) for b in payload)
    raise AssertionError(f"unknown encoding {encoding}")


def op_return_output(payload: bytes, encoding: str = "direct") -> bytes:
    script = bytes([OP_RETURN]) + pushed(payload, encoding)
    # The whole output must fit the device's 100-byte output buffer.
    assert 8 + 1 + len(script) <= 100
    return struct.pack("<Q", 0) + bytes([len(script)]) + script


def payment_output(amount: int) -> bytes:
    return (struct.pack("<Q", amount) + bytes([len(RECIPIENT_P2PKH)])
            + RECIPIENT_P2PKH)


def prevout_of(psbt_name: str):
    psbt = PSBT()
    psbt.deserialize(open(f"{tests_root}/psbt/singlesig/{psbt_name}", "r").read())
    prevtx = bitcoinTransaction(psbt.inputs[0].non_witness_utxo.serialize())
    return prevtx, psbt.tx.vin[0].prevout.n, psbt.tx.nVersion


def review_two_outputs(model: Firmware) -> Instructions:
    """The OP_RETURN output is displayed too, so there are two to approve."""
    instructions = Instructions(model)
    if model.name.startswith("nano"):
        instructions.new_request("Accept")   # the OP_RETURN output
        instructions.same_request("Accept")  # the payment
        instructions.same_request("Accept")  # fees, "Accept and send"
    else:
        instructions.review_start(output_count=2)
        instructions.review_fees()
        instructions.confirm_transaction()
    return instructions


def drive_to_outputs(client: RaggerClient, outputs: bytes) -> bytes:
    """Streams a one-input transaction and returns the finalize APDU."""
    prevtx, index, version = prevout_of("pkh-1to1.psbt")
    backend = client.app.dongle.transport_client

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

    return bytes([CLA, INS_HASH_INPUT_FINALIZE_FULL, FINALIZE_P1_LAST, 0x00,
                  len(outputs)]) + outputs


def finalize_status(client: RaggerClient, outputs: bytes) -> int:
    apdu = drive_to_outputs(client, outputs)
    backend = client.app.dongle.transport_client
    try:
        return backend.exchange_raw(apdu).status
    except ExceptionRAPDU as e:
        return e.status


class TestOpReturnOmni:

    @pytest.mark.parametrize(
        "encoding",
        ["direct", "pushdata1", "pushdata2", "pushdata4", "split"])
    def test_omni_payload_is_refused(self, client: RaggerClient, encoding: str):
        """No push encoding may carry an Omni payload past the check.

        `pushdata4` is V-038 on its own: it puts the marker four bytes further
        along than OP_PUSHDATA2 does, which is what the fixed-offset attempt
        missed. `split` is the case no single-push check can catch.
        """
        outputs = (b"\x02"
                   + op_return_output(OMNI_SIMPLE_SEND, encoding)
                   + payment_output(500))
        status = finalize_status(client, outputs)

        assert status == SW_TECHNICAL_PROBLEM_2, (
            f"Omni payload pushed as {encoding} was accepted: got "
            f"0x{status:04X}, expected 0x{SW_TECHNICAL_PROBLEM_2:04X}"
        )

    def test_plain_op_return_is_accepted(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        """A non-Omni OP_RETURN must still sign.

        Ledger Live sends these on Bitcoin, so a fix that bans OP_RETURN
        outright passes every refusal test above and breaks the wallet. This is
        the test that catches that.
        """
        outputs = (b"\x02"
                   + op_return_output(LEDGER_LIVE_PAYLOAD)
                   + payment_output(500))
        apdu = drive_to_outputs(client, outputs)

        instructions = review_two_outputs(firmware)
        client.app.dongle.set_navigation(True, navigator, test_name, instructions)
        client.app.dongle.exchange(bytearray(apdu))
        client.app.dongle.set_navigation(False, navigator, test_name, instructions)

        status = client.app.dongle.last_async_response().status
        assert status != SW_TECHNICAL_PROBLEM_2, (
            "a plain OP_RETURN was refused; this breaks Ledger Live's "
            "Wallet API and swap paths on Bitcoin"
        )

    def test_malformed_push_is_refused(self, client: RaggerClient):
        """A push running past the script end must fail closed."""
        script = bytes([OP_RETURN, 0x20, 0x41])  # declares 32 bytes, supplies 1
        outputs = (b"\x02"
                   + struct.pack("<Q", 0) + bytes([len(script)]) + script
                   + payment_output(500))
        status = finalize_status(client, outputs)

        assert status == SW_TECHNICAL_PROBLEM_2, (
            f"truncated push was accepted: got 0x{status:04X}"
        )


@pytest.mark.skip(reason="V-016 pre-fix behaviour; unskip on an unfixed build")
class TestOpReturnOmniVulnerable:
    """What the finding looked like. This passed before the fix."""

    def test_omni_payload_is_signed_unshown(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        outputs = (b"\x02"
                   + op_return_output(OMNI_SIMPLE_SEND)
                   + payment_output(500))
        apdu = drive_to_outputs(client, outputs)

        instructions = review_two_outputs(firmware)
        client.app.dongle.set_navigation(True, navigator, test_name, instructions)
        client.app.dongle.exchange(bytearray(apdu))
        client.app.dongle.set_navigation(False, navigator, test_name, instructions)

        assert client.app.dongle.last_async_response().status != \
            SW_TECHNICAL_PROBLEM_2
