"""Non-regression tests for Cerberus V-002 (lib-app-bitcoin).

GET WALLET PUBLIC KEY only checked that one data byte was there. With P1=01 the
path was formatted for display before anything parsed it, and format_path
guards the component count with LEDGER_ASSERT: a count of 11 or more ended the
app. The path was also never checked against Lc, so a count larger than the
data read components left in the buffer by the previous command.

A count over 10 is now refused with 0x6A80, and data shorter than the path
with 0x6700, both before the display and through io_send_sw, so the app stays
open.

TestPublicKeyPathVulnerable is the pre-fix behaviour, kept skipped so the
finding stays reproducible on an unfixed build.
"""
import struct
import time

import pytest
import requests

from ragger_bitcoin import RaggerClient

from test_message_session import KEY_PATH, apdu, status_of

INS_GET_WALLET_PUBLIC_KEY = 0x40
INS_SIGN_MESSAGE = 0x4E
P1_NO_DISPLAY, P1_DISPLAY = 0x00, 0x01
P2_LEGACY = 0x00
P1_PREPARE, P2_FIRST = 0x00, 0x01

SW_OK = 0x9000
SW_INCORRECT_LENGTH = 0x6700
SW_INCORRECT_DATA = 0x6A80

KEY_PATH_STR = "44'/1'/0'/0/0"

# Ten components, the most a path may have: 41 bytes with the count. It starts
# with 44'/1' because the app may only derive under */1', and its coin type
# matches, so the key is returned without a display.
LONGEST_PATH = bytes([10]) + b"".join(
    struct.pack(">I", c) for c in (0x8000002C, 0x80000001) + (0,) * 8)

# Eleven components is one more than the app allows.
TOO_LONG = bytes([11]) + b"".join(struct.pack(">I", i) for i in range(11))

OVERSIZED_COUNTS = [
    pytest.param(TOO_LONG, id="count_11_complete"),
    pytest.param(b"\xff", id="count_255_alone"),
]


def app_asserted(backend, timeout: float = 5.0) -> bool:
    """True once the app shows "App error" or the Speculos API goes away.

    With a display the SDK paints the assert screen and waits; headless it
    exits at once and takes the API with it.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if backend.compare_screen_with_text("App error"):
                return True
        except (OSError, requests.exceptions.RequestException):
            return True
        time.sleep(0.2)
    return False


def plant_key_path(backend) -> None:
    """Leaves KEY_PATH at the start of the data area for the next command.

    The SIGN MESSAGE reply is one byte, so it does not reach those offsets.
    """
    message = b"plant"
    data = KEY_PATH + struct.pack(">H", len(message)) + message
    reply = backend.exchange_raw(apdu(INS_SIGN_MESSAGE, P1_PREPARE, P2_FIRST, data))
    assert reply.status == SW_OK, f"got 0x{reply.status:04X}"


def public_key(backend, p1: int, data: bytes) -> int:
    return status_of(backend, apdu(INS_GET_WALLET_PUBLIC_KEY, p1, P2_LEGACY, data))


class TestPublicKeyPath:

    @pytest.mark.parametrize("data", [KEY_PATH, LONGEST_PATH],
                             ids=["bip44", "ten_components"])
    def test_control_complete_path(self, client: RaggerClient, data: bytes):
        """Catches a length check that is off by one and refuses it."""
        status = public_key(client.app.dongle.transport_client, P1_NO_DISPLAY, data)
        assert status == SW_OK, f"got 0x{status:04X}"

    @pytest.mark.parametrize("data", OVERSIZED_COUNTS)
    def test_displayed_oversized_count_is_refused(self, client: RaggerClient,
                                                  data: bytes):
        backend = client.app.dongle.transport_client
        status = public_key(backend, P1_DISPLAY, data)
        assert status == SW_INCORRECT_DATA, f"got 0x{status:04X}"
        # The app is still there to answer.
        status = public_key(backend, P1_NO_DISPLAY, KEY_PATH)
        assert status == SW_OK, f"got 0x{status:04X}"

    def test_count_alone_is_refused(self, client: RaggerClient):
        backend = client.app.dongle.transport_client
        plant_key_path(backend)
        status = public_key(backend, P1_NO_DISPLAY, KEY_PATH[:1])
        assert status == SW_INCORRECT_LENGTH, f"got 0x{status:04X}"


@pytest.mark.skip(reason="V-002 pre-fix behaviour; unskip on an unfixed build")
class TestPublicKeyPathVulnerable:
    """What the finding looked like. Each test passed before the fix."""

    @pytest.mark.parametrize("data", OVERSIZED_COUNTS)
    def test_displayed_oversized_count_kills_the_app(self, client: RaggerClient,
                                                     data: bytes):
        backend = client.app.dongle.transport_client
        # No reply comes back, so do not wait for one.
        backend.send_raw(apdu(INS_GET_WALLET_PUBLIC_KEY, P1_DISPLAY, P2_LEGACY,
                              data))
        assert app_asserted(backend), "the app survived an oversized path count"

    def test_count_alone_derives_from_stale_bytes(self, client: RaggerClient):
        backend = client.app.dongle.transport_client
        expected = bytes(client.app.getWalletPublicKey(KEY_PATH_STR)["publicKey"])
        plant_key_path(backend)
        # Only the count byte is sent: the 20 path bytes are the planted ones.
        reply = backend.exchange_raw(apdu(INS_GET_WALLET_PUBLIC_KEY, P1_NO_DISPLAY,
                                          P2_LEGACY, KEY_PATH[:1]))
        assert reply.status == SW_OK, f"got 0x{reply.status:04X}"
        data = bytes(reply.data)
        assert data[1:1 + data[0]] == expected, "not the planted path's key"
