"""Non-regression tests for lib-app-bitcoin-dev#31.

An approved signing pass ends sign-ready, and HASH SIGN finalizes the hash and
signs it. Nothing left the sign-ready state afterwards, so the host could send
HASH SIGN again and get a second signature with no review. The hash was
already final: SHA-256 coins signed a garbage digest, and on Overwinter coins
(ZCash, Komodo, ZClassic) the second finalization wrote nothing, so the funded
key signed leftover stack bytes. A rejected sign-path warning left the same
state behind.

Each pass now gives one signature: signing, or rejecting the sign-path
warning, ends the transaction.

TestHashSignRepeatVulnerable is the pre-fix behaviour, kept skipped so the
finding stays reproducible on an unfixed build.
"""
import struct

import pytest

from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID

from ragger_bitcoin import RaggerClient
from ragger_bitcoin.ragger_instructions import Instructions

from test_interleaved_command import (INS_HASH_SIGN, SIGHASH_ALL,
                                      UNUSUAL_SIGN_PATH, apdu)
from test_message_after_approval import approve_transaction, hash_sign
from test_review_restart import navigated_status

SW_OK = 0x9000
SW_CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985


def reject_sign_path(model: Firmware) -> Instructions:
    instructions = Instructions(model)
    if model.name.startswith("nano"):
        instructions.new_request("Reject")
    else:
        instructions.new_request("Unusual", NavInsID.USE_CASE_REVIEW_TAP,
                                 NavInsID.USE_CASE_CHOICE_REJECT)
    return instructions.no_snapshots()


def unusual_hash_sign() -> bytes:
    return apdu(INS_HASH_SIGN, 0x00, 0x00, UNUSUAL_SIGN_PATH + b"\x00"
                + struct.pack(">I", 0) + bytes([SIGHASH_ALL]))


class TestHashSignRepeat:

    def test_second_hash_sign_is_refused(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        approve_transaction(client, navigator, firmware, test_name)
        backend = client.app.dongle.transport_client
        status = hash_sign(backend)
        assert status == SW_OK, f"got 0x{status:04X}"

        status = hash_sign(backend)
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, (
            f"got 0x{status:04X}; 0x{SW_OK:04X} means a second signature "
            "came out of one approval")

    def test_sign_after_rejected_sign_path_is_refused(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        approve_transaction(client, navigator, firmware, test_name)
        status = navigated_status(client, navigator, f"{test_name}_path",
                                  reject_sign_path(firmware),
                                  unusual_hash_sign())
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, \
            f"got 0x{status:04X}"

        status = hash_sign(client.app.dongle.transport_client)
        assert status == SW_CONDITIONS_OF_USE_NOT_SATISFIED, \
            f"got 0x{status:04X}"


@pytest.mark.skip(reason="#31 pre-fix behaviour; unskip on an unfixed build")
class TestHashSignRepeatVulnerable:
    """What the finding looked like. This passed before the fix."""

    def test_second_hash_sign_signs_again(
            self, navigator: Navigator, firmware: Firmware,
            client: RaggerClient, test_name: str):
        approve_transaction(client, navigator, firmware, test_name)
        backend = client.app.dongle.transport_client
        assert hash_sign(backend) == SW_OK

        status = hash_sign(backend)
        assert status == SW_OK, f"got 0x{status:04X}"
