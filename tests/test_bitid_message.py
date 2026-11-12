"""Non-regression tests for Cerberus V-007 (lib-app-bitcoin).

A message signing path with a BitID marker (0xB11D or 0xB11E) in the low 16
bits of any component used to be signed at once, with no prompt. The match
ignored the position, the hardening and the upper 16 bits, so an ordinary BIP44
address index such as 45341 (0xB11D) triggered it.

Silent BitID signing is gone: every message signature goes through the prompt.
Rejecting it replies 0x6985 through io_send_sw, so the app stays open.

TestBitidMessageVulnerable is the pre-fix behaviour, kept skipped so the
finding stays reproducible on an unfixed build.
"""
import hashlib
import struct

import pytest

from ecdsa import SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der

from ledger_bitcoin.btchip.btchipHelpers import parse_bip32_path

from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware
from ragger.navigator import Navigator

from ragger_bitcoin import RaggerClient
from ragger_bitcoin.ragger_instructions import Instructions

from test_message_session import reject_message

CLA = 0xE0
INS_SIGN_MESSAGE = 0x4E
P1_PREPARE, P1_SIGN = 0x00, 0x80
P2_FIRST = 0x01

SW_OK = 0x9000
SW_CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985

# The testnet build signs with the "Bitcoin" message magic.
MAGIC = b"\x18Bitcoin Signed Message:\n"
MESSAGE = b"silent"

MARKER_PATHS = [
    pytest.param("44'/1'/0'/0/45341", id="bip44_index_b11d"),
    pytest.param("44'/1'/0'/0/45342", id="bip44_index_b11e"),
    pytest.param("44'/1'/45341'", id="hardened_b11d"),
    pytest.param(f"44'/1'/0'/0/{0x1234B11D}", id="upper_bits_b11d"),
]

SIGN = bytes([CLA, INS_SIGN_MESSAGE, P1_SIGN, 0x00, 1, 0x00])


def prepare(client: RaggerClient, path: str) -> None:
    data = bytes(parse_bip32_path(path)) + struct.pack(">H", len(MESSAGE)) + MESSAGE
    status = client.app.dongle.transport_client.exchange_raw(
        bytes([CLA, INS_SIGN_MESSAGE, P1_PREPARE, P2_FIRST, len(data)]) + data).status
    assert status == SW_OK, f"got 0x{status:04X}"


def message_digest(message: bytes) -> bytes:
    assert len(message) < 0xFD
    data = MAGIC + bytes([len(message)]) + message
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def verifies(client: RaggerClient, path: str, reply: bytes) -> bool:
    pub = bytes(client.app.getWalletPublicKey(path)["publicKey"])
    key = VerifyingKey.from_string(pub, curve=SECP256k1)
    # The first byte carries the parity of R on top of the DER tag.
    der = bytes([0x30]) + reply[1:]
    return key.verify_digest(der, message_digest(MESSAGE),
                             sigdecode=sigdecode_der)


def approve_message(model: Firmware) -> Instructions:
    instructions = Instructions(model)
    if model.name.startswith("nano"):
        instructions.nano_skip_screen("Message")
        instructions.same_request("Sign")
    else:
        instructions.confirm_message()
    return instructions.no_snapshots()


def navigated_sign(client: RaggerClient, navigator: Navigator, name: str,
                   instructions: Instructions):
    client.app.dongle.set_navigation(True, navigator, name, instructions)
    try:
        client.app.dongle.exchange(bytearray(SIGN))
        reply = client.app.dongle.last_async_response()
        status, data = reply.status, bytes(reply.data)
    except ExceptionRAPDU as e:
        status, data = e.status, b""
    client.app.dongle.set_navigation(False, navigator, name, instructions)
    return status, data


class TestBitidMessage:

    def test_control_marker_path_signs_after_approval(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        """Catches a fix that refuses BitID paths instead of prompting for them."""
        path = "44'/1'/0'/0/45341"
        prepare(client, path)
        status, data = navigated_sign(client, navigator, test_name,
                                      approve_message(firmware))
        assert status == SW_OK, f"got 0x{status:04X}"
        assert verifies(client, path, data)

    @pytest.mark.parametrize("path", MARKER_PATHS)
    def test_marker_path_prompts(self, navigator: Navigator, firmware: Firmware,
                                 client: RaggerClient, test_name: str, path: str):
        """The rejection can only be reached through the prompt."""
        prepare(client, path)
        status, _ = navigated_sign(client, navigator, test_name,
                                   reject_message(firmware))
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, f"got 0x{status:04X}"


@pytest.mark.skip(reason="V-007 pre-fix behaviour; unskip on an unfixed build")
class TestBitidMessageVulnerable:
    """What the finding looked like. This passed before the fix."""

    @pytest.mark.parametrize("path", MARKER_PATHS)
    def test_marker_path_signs_without_prompt(self, client: RaggerClient,
                                              path: str):
        prepare(client, path)
        # A fixed build opens the prompt here, and this exchange waits for it.
        reply = client.app.dongle.transport_client.exchange_raw(SIGN)
        assert reply.status == SW_OK, f"got 0x{reply.status:04X}"
        assert verifies(client, path, bytes(reply.data))
