"""Non-regression tests for Cerberus V-019 (lib-app-bitcoin).

The first SIGN MESSAGE chunk, HASH SIGN and the first GET TRUSTED INPUT chunk
read their header fields without checking them against Lc. A command shorter
than its own header made the app read past the bytes it was sent: leftovers
of the previous command, and for SIGN MESSAGE and HASH SIGN up to about 35
bytes past the end of the APDU buffer.

A command shorter than its header is now refused with 0x6700 through
io_send_sw, so the app stays open. A refused message ends its session, and a
refused HASH SIGN ends the transaction.

TestShortApduVulnerable is the pre-fix behaviour, kept skipped so the finding
stays reproducible on an unfixed build.
"""
import struct

import pytest

from ragger.firmware import Firmware
from ragger.navigator import Navigator

from ragger_bitcoin import RaggerClient

from test_message_after_approval import approve_transaction, hash_sign
from test_message_session import KEY_PATH, apdu, status_of

INS_GET_TRUSTED_INPUT = 0x42
INS_HASH_SIGN = 0x48
INS_SIGN_MESSAGE = 0x4E
P1_PREPARE = 0x00
P2_LEGACY, P2_FIRST, P2_OTHER = 0x00, 0x01, 0x80

SW_OK = 0x9000
SW_INCORRECT_LENGTH = 0x6700
SW_CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985
SW_INCORRECT_DATA = 0x6A80

# Ten components, the most a path may have: 41 bytes with the count.
LONG_PATH = bytes([10]) + b"".join(struct.pack(">I", i) for i in range(10))

# A message header cut by one byte: the length field is incomplete or missing.
SHORT_MESSAGE_HEADERS = [
    pytest.param(P2_FIRST, LONG_PATH + b"\x00", id="first"),
    pytest.param(P2_LEGACY, LONG_PATH, id="legacy"),
]

# The same header, complete, with the message to follow in a second chunk.
EXACT_MESSAGE_HEADERS = [
    pytest.param(P2_FIRST, LONG_PATH + b"\x00\x01", id="first"),
    pytest.param(P2_LEGACY, LONG_PATH + b"\x01", id="legacy"),
]


def plant(backend) -> None:
    """Leaves 0xFF at data offsets 41 and 42 for the next command to pick up.

    The reply is one or two bytes, so it does not reach those offsets.
    """
    message = b"A" * 18 + b"\xff\xff"
    data = KEY_PATH + struct.pack(">H", len(message)) + message
    assert len(data) == 43
    reply = backend.exchange_raw(apdu(INS_SIGN_MESSAGE, P1_PREPARE, P2_FIRST, data))
    assert reply.status == SW_OK, f"got 0x{reply.status:04X}"


def short_hash_sign(backend) -> int:
    """Path and authorization length only: lock time and sighash are missing."""
    return status_of(backend, apdu(INS_HASH_SIGN, 0x00, 0x00, KEY_PATH + b"\x00"))


class TestShortApdu:

    @pytest.mark.parametrize("p2,data", EXACT_MESSAGE_HEADERS)
    def test_control_message_exact_header(self, client: RaggerClient,
                                          p2: int, data: bytes):
        """A header with nothing after it is still complete.

        Catches a check that is off by one and refuses it.
        """
        backend = client.app.dongle.transport_client
        reply = backend.exchange_raw(apdu(INS_SIGN_MESSAGE, P1_PREPARE, p2, data))
        assert reply.status == SW_OK, f"got 0x{reply.status:04X}"
        assert bytes(reply.data) == b"\x00"

        reply = backend.exchange_raw(apdu(INS_SIGN_MESSAGE, P1_PREPARE, P2_OTHER,
                                          b"x"))
        assert reply.status == SW_OK, f"got 0x{reply.status:04X}"
        assert bytes(reply.data) == b"\x00\x00"

    @pytest.mark.parametrize("p2,data", SHORT_MESSAGE_HEADERS)
    def test_message_short_header_is_refused(self, client: RaggerClient,
                                             p2: int, data: bytes):
        backend = client.app.dongle.transport_client
        plant(backend)
        status = status_of(backend, apdu(INS_SIGN_MESSAGE, P1_PREPARE, p2, data))
        assert status == SW_INCORRECT_LENGTH, f"got 0x{status:04X}"

        # Neither the planted message nor the refused one may be continued.
        status = status_of(backend, apdu(INS_SIGN_MESSAGE, P1_PREPARE, P2_OTHER,
                                         b"x"))
        assert status == SW_INCORRECT_DATA, f"got 0x{status:04X}"

    @pytest.mark.parametrize("data", [b"\x00", b"\x00\x00\x00"],
                             ids=["1_byte", "3_bytes"])
    def test_trusted_input_short_first_is_refused(self, client: RaggerClient,
                                                  data: bytes):
        backend = client.app.dongle.transport_client
        status = status_of(backend, apdu(INS_GET_TRUSTED_INPUT, 0x00, 0x00, data))
        assert status == SW_INCORRECT_LENGTH, f"got 0x{status:04X}"

    def test_control_hash_sign_after_approval(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        """A complete HASH SIGN must still sign."""
        approve_transaction(client, navigator, firmware, test_name)
        status = hash_sign(client.app.dongle.transport_client)
        assert status == SW_OK, f"got 0x{status:04X}"

    def test_hash_sign_short_is_refused(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        approve_transaction(client, navigator, firmware, test_name)
        backend = client.app.dongle.transport_client
        status = short_hash_sign(backend)
        assert status == SW_INCORRECT_LENGTH, f"got 0x{status:04X}"

        # The refusal ended the transaction, so a complete one cannot follow.
        status = hash_sign(backend)
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, f"got 0x{status:04X}"


@pytest.mark.skip(reason="V-019 pre-fix behaviour; unskip on an unfixed build")
class TestShortApduVulnerable:
    """What the finding looked like. Each test passed before the fix."""

    def test_message_first_hashes_255_bytes_from_42(self, client: RaggerClient):
        backend = client.app.dongle.transport_client
        plant(backend)
        # Declares a 2-byte length at offset 41 but sends only its first byte.
        # The second (0xFF) is stale, and 42 - 43 wraps to a 255-byte chunk.
        reply = backend.exchange_raw(apdu(INS_SIGN_MESSAGE, P1_PREPARE, P2_FIRST,
                                          LONG_PATH + b"\x00"))
        assert reply.status == SW_OK, f"got 0x{reply.status:04X}"
        # 0x00 0x00 means the whole declared message has been hashed.
        assert bytes(reply.data) == b"\x00\x00"

    def test_message_legacy_hashes_255_bytes_from_41(self, client: RaggerClient):
        backend = client.app.dongle.transport_client
        plant(backend)
        # The 1-byte length is not sent at all: it is the stale 0xFF.
        reply = backend.exchange_raw(apdu(INS_SIGN_MESSAGE, P1_PREPARE, P2_LEGACY,
                                          LONG_PATH))
        assert reply.status == SW_OK, f"got 0x{reply.status:04X}"
        assert bytes(reply.data) == b"\x00\x00"

    def test_trusted_input_first_parses_past_lc(self, client: RaggerClient):
        backend = client.app.dongle.transport_client
        # The 4-byte output index is cut to 1 byte, and 1 - 4 wraps to 253.
        status = status_of(backend, apdu(INS_GET_TRUSTED_INPUT, 0x00, 0x00,
                                         b"\x00"))
        assert status != SW_INCORRECT_LENGTH, "the short command was refused"

    def test_hash_sign_reads_past_lc(self, navigator: Navigator,
                                     firmware: Firmware, client: RaggerClient,
                                     test_name: str):
        approve_transaction(client, navigator, firmware, test_name)
        # The app reads lock time and sighash from stale bytes, then rejects
        # the sighash or signs.
        status = short_hash_sign(client.app.dongle.transport_client)
        assert status != SW_INCORRECT_LENGTH, "the short command was refused"
