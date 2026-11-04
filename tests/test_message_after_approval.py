"""Non-regression tests for Cerberus V-036 (lib-app-bitcoin).

Message signing and transaction signing share one running hash. Preparing a
message rewrote that hash but left an approved transaction in its sign-ready
state, so HASH SIGN still signed - now over the message bytes, with no message
review.

The hashes now have an owner. Preparing a message takes them, and a
transaction may only finalize, sign or carry on parsing while it still owns
them. HASH SIGN and FINALIZE answer 0x6985 through io_send_sw; a parse that
carries on fails its LEDGER_ASSERT and ends the app.

TestMessageAfterApprovalVulnerable is the pre-fix behaviour, kept skipped so
the finding stays reproducible on an unfixed build.
"""
import struct

import pytest

from ragger.firmware import Firmware
from ragger.navigator import Navigator

from ragger_bitcoin import RaggerClient

from test_parser_mode_switch import (DEFAULT_SEQUENCE, apdu, input_chunk,
                                     outputs_blob, prevout_of, run_pass,
                                     status_of)
from test_trusted_input_key import wait_until_refused

INS_HASH_INPUT_START = 0x44
INS_HASH_SIGN = 0x48
INS_HASH_INPUT_FINALIZE_FULL = 0x4A
INS_SIGN_MESSAGE = 0x4E

P1_FIRST, P1_NEXT = 0x00, 0x80
P2_NEW = 0x00
FINALIZE_P1_LAST = 0x80

SW_OK = 0x9000
SW_CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985

SIGHASH_ALL = 0x01

# m/44'/1'/0'/0/0
KEY_PATH = bytes([5]) + b"".join(
    struct.pack(">I", c) for c in (0x8000002C, 0x80000001, 0x80000000, 0, 0))


def approve_transaction(client, navigator, firmware, test_name):
    """Runs a first signing pass and approves it, leaving the app sign-ready."""
    prevtx, index, version = prevout_of("pkh-1to1.psbt")
    token_a = bytes(client.app.getTrustedInput(prevtx, index)["value"])
    token_b = bytes(client.app.getTrustedInput(prevtx, index)["value"])
    status = run_pass(client, version, [token_a, token_b], first=True,
                      steal=False, navigator=navigator, firmware=firmware,
                      test_name=test_name)
    assert status == SW_OK, f"approval failed with 0x{status:04X}"


def hash_sign(backend) -> int:
    data = KEY_PATH + b"\x00" + struct.pack(">I", 0) + bytes([SIGHASH_ALL])
    return status_of(backend, apdu(INS_HASH_SIGN, 0x00, 0x00, data))


def prepare_message(backend) -> int:
    data = KEY_PATH + struct.pack(">H", 2) + b"hi"
    return status_of(backend, apdu(INS_SIGN_MESSAGE, 0x00, 0x01, data))


def start_one_input(client):
    """Starts a one-input signing pass; returns the backend and the input."""
    prevtx, index, version = prevout_of("pkh-1to1.psbt")
    token = bytes(client.app.getTrustedInput(prevtx, index)["value"])
    backend = client.app.dongle.transport_client
    assert status_of(backend, apdu(INS_HASH_INPUT_START, P1_FIRST, P2_NEW,
                                   struct.pack("<I", version) + b"\x01")) == SW_OK
    return backend, token


class TestMessageAfterApproval:

    def test_control_sign_after_approval(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        """An approved transaction must still be signed.

        Catches a fix that clears the sign-ready state too eagerly.
        """
        approve_transaction(client, navigator, firmware, test_name)
        backend = client.app.dongle.transport_client

        status = hash_sign(backend)
        assert status == SW_OK, f"got 0x{status:04X}"

    def test_sign_after_message_prepare_is_refused(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        approve_transaction(client, navigator, firmware, test_name)
        backend = client.app.dongle.transport_client
        assert prepare_message(backend) == SW_OK

        status = hash_sign(backend)
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, f"got 0x{status:04X}"

    def test_finalize_after_message_prepare_is_refused(
            self, client: RaggerClient):
        """Outputs must not be hashed into a message started after the inputs."""
        backend, token = start_one_input(client)
        for chunk in (input_chunk(token), DEFAULT_SEQUENCE):
            assert status_of(backend, apdu(INS_HASH_INPUT_START, P1_NEXT,
                                           P2_NEW, chunk)) == SW_OK
        assert prepare_message(backend) == SW_OK

        status = status_of(backend, apdu(INS_HASH_INPUT_FINALIZE_FULL,
                                         FINALIZE_P1_LAST, 0x00,
                                         outputs_blob(500000)))
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, f"got 0x{status:04X}"


class TestParseAfterMessagePrepare:

    def test_parse_after_message_prepare_is_refused(
            self, client: RaggerClient):
        """A transaction parse must not carry on into a message's hash.

        Last in its class, since refusal exits the app.
        """
        backend, token = start_one_input(client)
        assert prepare_message(backend) == SW_OK

        backend.send_raw(apdu(INS_HASH_INPUT_START, P1_NEXT, P2_NEW,
                              input_chunk(token)))
        wait_until_refused(backend)


@pytest.mark.skip(reason="V-036 pre-fix behaviour; unskip on an unfixed build")
class TestMessageAfterApprovalVulnerable:
    """What the finding looked like. This passed before the fix."""

    def test_sign_after_message_prepare_is_accepted(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        approve_transaction(client, navigator, firmware, test_name)
        backend = client.app.dongle.transport_client
        assert prepare_message(backend) == SW_OK

        assert hash_sign(backend) == SW_OK
