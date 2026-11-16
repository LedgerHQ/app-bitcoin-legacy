"""Non-regression tests for Cerberus V-001 (lib-app-bitcoin).

SET OPERATION MODE joined its length and value checks with && instead of ||.
With Lc=0 the SDK parser hands the handler a NULL data pointer, the length test
was true, and the handler read ptr[0]: the app died. The same mistake accepted
any one-byte mode and any longer command that started with the wallet mode.

Only one byte holding the wallet mode is now accepted. A wrong length replies
0x6700 and a wrong mode 0x6A80, both through io_send_sw, so the app stays open.

TestSetOperationModeVulnerable is the pre-fix behaviour, kept skipped so the
finding stays reproducible on an unfixed build.
"""
import time

import pytest
import requests

from ragger_bitcoin import RaggerClient

from test_message_session import apdu, status_of

INS_GET_OPERATION_MODE = 0x24
INS_SET_OPERATION_MODE = 0x26
MODE_WALLET = 0x01

SW_OK = 0x9000
SW_INCORRECT_LENGTH = 0x6700
SW_INCORRECT_DATA = 0x6A80


def app_died(backend, timeout: float = 5.0) -> bool:
    """True once the Speculos API stops answering, False if it still does."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            backend.compare_screen_with_text("App error")
        except (OSError, requests.exceptions.RequestException):
            return True
        time.sleep(0.2)
    return False


def operation_mode(backend) -> bytes:
    reply = backend.exchange_raw(apdu(INS_GET_OPERATION_MODE, 0x00, 0x00, b""))
    assert reply.status == SW_OK, f"got 0x{reply.status:04X}"
    return bytes(reply.data)


def set_operation_mode(backend, data: bytes) -> int:
    return status_of(backend, apdu(INS_SET_OPERATION_MODE, 0x00, 0x00, data))


class TestSetOperationMode:

    def test_control_wallet_mode(self, client: RaggerClient):
        backend = client.app.dongle.transport_client
        status = set_operation_mode(backend, bytes([MODE_WALLET]))
        assert status == SW_OK, f"got 0x{status:04X}"
        assert operation_mode(backend) == bytes([MODE_WALLET])

    def test_empty_command_is_refused(self, client: RaggerClient):
        backend = client.app.dongle.transport_client
        status = set_operation_mode(backend, b"")
        assert status == SW_INCORRECT_LENGTH, f"got 0x{status:04X}"
        # The app is still there to answer.
        assert operation_mode(backend) == bytes([MODE_WALLET])

    def test_unknown_mode_is_refused(self, client: RaggerClient):
        backend = client.app.dongle.transport_client
        status = set_operation_mode(backend, b"\x02")
        assert status == SW_INCORRECT_DATA, f"got 0x{status:04X}"

    def test_trailing_byte_is_refused(self, client: RaggerClient):
        backend = client.app.dongle.transport_client
        status = set_operation_mode(backend, bytes([MODE_WALLET, 0x00]))
        assert status == SW_INCORRECT_LENGTH, f"got 0x{status:04X}"


@pytest.mark.skip(reason="V-001 pre-fix behaviour; unskip on an unfixed build")
class TestSetOperationModeVulnerable:
    """What the finding looked like. Each test passed before the fix."""

    def test_empty_command_kills_the_app(self, client: RaggerClient):
        backend = client.app.dongle.transport_client
        # No reply comes back, so do not wait for one.
        backend.send_raw(apdu(INS_SET_OPERATION_MODE, 0x00, 0x00, b""))
        assert app_died(backend), "the app survived an empty SET OPERATION MODE"

    def test_unknown_mode_is_accepted(self, client: RaggerClient):
        backend = client.app.dongle.transport_client
        status = set_operation_mode(backend, b"\x02")
        assert status == SW_OK, f"got 0x{status:04X}"

    def test_trailing_byte_is_accepted(self, client: RaggerClient):
        backend = client.app.dongle.transport_client
        status = set_operation_mode(backend, bytes([MODE_WALLET, 0x00]))
        assert status == SW_OK, f"got 0x{status:04X}"
