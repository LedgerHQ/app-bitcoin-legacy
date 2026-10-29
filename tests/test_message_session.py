"""Non-regression tests for Cerberus V-042 (lib-app-bitcoin).

Message signing and transaction signing share one running hash. Starting a
transaction parse (HASH INPUT START or GET TRUSTED INPUT) rewrites that hash
but used to leave a pending message's length counters alone, so the message
could still be continued and signed over bytes it never owned.

A transaction parse now ends any pending message, so continuing or signing it
is refused with 0x6A80. Refusals here go through io_send_sw and do not exit the
app.

TestMessageSessionVulnerable is the pre-fix behaviour, kept skipped so the
finding stays reproducible on an unfixed build.
"""
import struct

import pytest

from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware
from ragger.navigator import Navigator

from ragger_bitcoin import RaggerClient
from ragger_bitcoin.ragger_instructions import Instructions

CLA = 0xE0
INS_GET_TRUSTED_INPUT = 0x42
INS_HASH_INPUT_START = 0x44
INS_SIGN_MESSAGE = 0x4E

P1_PREPARE, P1_SIGN = 0x00, 0x80
P2_FIRST, P2_OTHER = 0x01, 0x80
HIS_P1_FIRST, HIS_P2_NEW = 0x00, 0x00

SW_OK = 0x9000
SW_CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985
SW_INCORRECT_DATA = 0x6A80

# m/44'/1'/0'/0/0
KEY_PATH = bytes([5]) + b"".join(
    struct.pack(">I", c) for c in (0x8000002C, 0x80000001, 0x80000000, 0, 0))

TX_VERSION = struct.pack("<I", 1)


def apdu(ins, p1, p2, data: bytes) -> bytes:
    return bytes([CLA, ins, p1, p2, len(data)]) + data


def status_of(backend, a: bytes) -> int:
    try:
        return backend.exchange_raw(a).status
    except ExceptionRAPDU as e:
        return e.status


def prepare_message(backend, declared: int, first_chunk: bytes) -> int:
    data = KEY_PATH + struct.pack(">H", declared) + first_chunk
    return status_of(backend, apdu(INS_SIGN_MESSAGE, P1_PREPARE, P2_FIRST, data))


def start_transaction(backend) -> int:
    return status_of(backend, apdu(INS_HASH_INPUT_START, HIS_P1_FIRST,
                                   HIS_P2_NEW, TX_VERSION + b"\x01"))


def start_trusted_input(backend) -> int:
    return status_of(backend, apdu(INS_GET_TRUSTED_INPUT, 0x00, 0x00,
                                   struct.pack(">I", 0) + TX_VERSION + b"\x01"))


def reject_message(model: Firmware) -> Instructions:
    instructions = Instructions(model)
    if model.name.startswith("nano"):
        instructions.new_request("Cancel")
    else:
        instructions.reject_message()
    return instructions


class TestMessageSession:

    def test_control_new_message_after_transaction_start(
            self, client: RaggerClient):
        """A message started after a transaction parse must still be accepted.

        Catches a fix that bans message signing instead of ending the old
        session.
        """
        backend = client.app.dongle.transport_client
        assert start_transaction(backend) == SW_OK
        assert prepare_message(backend, 2, b"hi") == SW_OK

    def test_continue_after_transaction_start_is_refused(
            self, client: RaggerClient):
        backend = client.app.dongle.transport_client
        assert prepare_message(backend, 2, b"h") == SW_OK
        assert start_transaction(backend) == SW_OK

        status = status_of(backend, apdu(INS_SIGN_MESSAGE, P1_PREPARE,
                                         P2_OTHER, b"i"))
        assert status == SW_INCORRECT_DATA, f"got 0x{status:04X}"

    def test_sign_after_transaction_start_is_refused(
            self, client: RaggerClient):
        """A complete message must not reach the prompt once a parse ran."""
        backend = client.app.dongle.transport_client
        assert prepare_message(backend, 2, b"hi") == SW_OK
        assert start_transaction(backend) == SW_OK

        status = status_of(backend, apdu(INS_SIGN_MESSAGE, P1_SIGN, 0x00,
                                         b"\x00"))
        assert status == SW_INCORRECT_DATA, f"got 0x{status:04X}"

    def test_continue_after_trusted_input_start_is_refused(
            self, client: RaggerClient):
        backend = client.app.dongle.transport_client
        assert prepare_message(backend, 2, b"h") == SW_OK
        assert start_trusted_input(backend) == SW_OK

        status = status_of(backend, apdu(INS_SIGN_MESSAGE, P1_PREPARE,
                                         P2_OTHER, b"i"))
        assert status == SW_INCORRECT_DATA, f"got 0x{status:04X}"

    def test_sign_after_rejection_is_refused(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        """A rejected message must not be offered for signing again."""
        backend = client.app.dongle.transport_client
        assert prepare_message(backend, 2, b"hi") == SW_OK

        instructions = reject_message(firmware)
        client.app.dongle.set_navigation(True, navigator, test_name, instructions)
        try:
            client.app.dongle.exchange(bytearray(apdu(INS_SIGN_MESSAGE, P1_SIGN,
                                                      0x00, b"\x00")))
            status = client.app.dongle.last_async_response().status
        except ExceptionRAPDU as e:
            status = e.status
        client.app.dongle.set_navigation(False, navigator, test_name, instructions)
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, f"got 0x{status:04X}"

        status = status_of(backend, apdu(INS_SIGN_MESSAGE, P1_SIGN, 0x00,
                                         b"\x00"))
        assert status == SW_INCORRECT_DATA, f"got 0x{status:04X}"


@pytest.mark.skip(reason="V-042 pre-fix behaviour; unskip on an unfixed build")
class TestMessageSessionVulnerable:
    """What the finding looked like. This passed before the fix."""

    def test_continue_after_transaction_start_is_accepted(
            self, client: RaggerClient):
        backend = client.app.dongle.transport_client
        assert prepare_message(backend, 2, b"h") == SW_OK
        assert start_transaction(backend) == SW_OK

        status = status_of(backend, apdu(INS_SIGN_MESSAGE, P1_PREPARE,
                                         P2_OTHER, b"i"))
        assert status == SW_OK
