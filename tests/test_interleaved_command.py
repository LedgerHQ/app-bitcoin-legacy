"""Non-regression tests for Cerberus V-049, V-050 and V-051 (lib-app-bitcoin).

A prompt holds its command's reply until the user answers. Both findings need
the host to send another command meanwhile, which rewrites the state the
pending approval acts on:

- V-049: a new message PREPARE while message A's prompt is open, so approving
  A signs the replacement.
- V-050: GET TRUSTED INPUT while a transaction review is open, so approving it
  promotes the trusted-input hash to a signable one.
- V-051: FINALIZE while an output prompt is open, so the output still buffered
  is counted twice and the fee screen understates the fee.

The app has no lock of its own. The SDK refuses any command while a reply is
pending, with 0x6901, from v26.6.1 on API level 26 and v27.1.0 on API level 27.
These tests pin that dependency: they fail on a build whose SDK lacks the lock.

Speculos's HTTP API serialises commands, so the overlap goes through its raw
APDU port. Each test leaves its prompt open; the backend is per test.
"""
import socket
import struct

from ragger.backend.interface import BackendInterface

from ragger_bitcoin import RaggerClient

from test_op_return_omni import drive_to_outputs, payment_output

CLA = 0xE0
INS_GET_TRUSTED_INPUT = 0x42
INS_HASH_INPUT_FINALIZE_FULL = 0x4A
INS_SIGN_MESSAGE = 0x4E

FINALIZE_P1_MORE = 0x00
FINALIZE_P1_LAST = 0x80

SW_OK = 0x9000
SW_COMMAND_NOT_ACCEPTED = 0x6901

# m/44'/1'/0'/0/0
KEY_PATH = bytes([5]) + b"".join(
    struct.pack(">I", c) for c in (0x8000002C, 0x80000001, 0x80000000, 0, 0))


def apdu(ins: int, p1: int, p2: int, data: bytes) -> bytes:
    return bytes([CLA, ins, p1, p2, len(data)]) + data


def prepare_message(message: bytes) -> bytes:
    return apdu(INS_SIGN_MESSAGE, 0x00, 0x01,
                KEY_PATH + struct.pack(">H", len(message)) + message)


class RawApdu:
    """Speculos's raw APDU port, which takes a command while one is pending."""

    def __init__(self, backend: BackendInterface):
        self._sock = socket.create_connection(("127.0.0.1", backend._apdu_port))
        # A missing reply must fail the test, not hang it.
        self._sock.settimeout(10)

    def send(self, data: bytes) -> None:
        self._sock.sendall(len(data).to_bytes(4, "big") + data)

    def status(self) -> int:
        size = int.from_bytes(self._recv(4), "big")
        reply = self._recv(size + 2)
        return int.from_bytes(reply[-2:], "big")

    def _recv(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = self._sock.recv(size - len(data))
            assert chunk, "Speculos closed the APDU connection"
            data += chunk
        return data


def open_prompt(backend: BackendInterface, command: bytes) -> RawApdu:
    raw = RawApdu(backend)
    raw.send(command)
    backend.wait_for_text_on_screen("Review|Sign")
    return raw


class TestInterleavedCommand:

    def test_message_prepare_during_message_prompt_is_refused(
            self, client: RaggerClient):
        """V-049: PREPARE(B) must not reach the app while A awaits approval."""
        backend = client.app.dongle.transport_client
        assert backend.exchange_raw(prepare_message(b"A")).status == SW_OK

        raw = open_prompt(backend, apdu(INS_SIGN_MESSAGE, 0x80, 0x00, b"\x00"))
        raw.send(prepare_message(b"B"))
        status = raw.status()
        assert status == SW_COMMAND_NOT_ACCEPTED, f"got 0x{status:04X}"

    def test_trusted_input_during_transaction_review_is_refused(
            self, client: RaggerClient):
        """V-050: GET TRUSTED INPUT must not restart the hashes under a review."""
        backend = client.app.dongle.transport_client

        raw = open_prompt(backend,
                          drive_to_outputs(client, b"\x01" + payment_output(500)))
        raw.send(apdu(INS_GET_TRUSTED_INPUT, 0x00, 0x00,
                      struct.pack(">I", 0) + struct.pack("<I", 1) + b"\x01"))
        status = raw.status()
        assert status == SW_COMMAND_NOT_ACCEPTED, f"got 0x{status:04X}"

    def test_finalize_during_output_review_is_refused(
            self, client: RaggerClient):
        """V-051: FINALIZE must not re-read the output under review."""
        backend = client.app.dongle.transport_client

        more = bytearray(drive_to_outputs(client, b"\x02" + payment_output(500)))
        more[2] = FINALIZE_P1_MORE
        raw = open_prompt(backend, bytes(more))
        raw.send(apdu(INS_HASH_INPUT_FINALIZE_FULL, FINALIZE_P1_LAST, 0x00,
                      payment_output(700)))
        status = raw.status()
        assert status == SW_COMMAND_NOT_ACCEPTED, f"got 0x{status:04X}"
