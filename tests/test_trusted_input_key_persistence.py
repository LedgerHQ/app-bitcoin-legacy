"""Persistence checks for the V-028 trusted-input key.

Speculos gives each app a blank NVRAM, so the other tests only ever exercise
first-boot generation. These two drive a real second boot through Speculos'
--save-nvram / --load-nvram, covering the two things that branch alone cannot
show: that the key survives a restart, and that the second boot reuses it
rather than writing a new one.

The pair is ordered - the first test produces the NVRAM image the second loads.
"""
import hmac
from hashlib import sha256
from pathlib import Path
from typing import List

import pytest

from ragger_bitcoin import RaggerClient

from test_trusted_input_key import prevout_of, TRUSTED_INPUT_SIZE

# Speculos writes <lib>_nvram.bin into the working directory, and the app is
# loaded as "main".
NVRAM_FILE = Path("main_nvram.bin")

STORAGE_MAGIC = 0x42544331     # lib-app-bitcoin/filesystem.h
KEY_OFFSET = 4                 # storage_t: uint32_t magic, then the 32-byte key
KEY_SIZE = 32


@pytest.fixture
def additional_speculos_arguments(request) -> List[str]:
    """Second boot restores the NVRAM; loading a missing file is fatal."""
    if request.node.get_closest_marker("nvram_reload"):
        return ["--load-nvram", "--save-nvram"]
    return ["--save-nvram"]


@pytest.fixture(scope="module", autouse=True)
def clean_nvram():
    """A stale image would let the second test pass without proving anything."""
    NVRAM_FILE.unlink(missing_ok=True)
    yield
    NVRAM_FILE.unlink(missing_ok=True)


def persisted_key() -> bytes:
    record = NVRAM_FILE.read_bytes()
    assert len(record) >= KEY_OFFSET + KEY_SIZE, f"short NVRAM image ({len(record)}B)"
    magic = int.from_bytes(record[:KEY_OFFSET], "little")
    assert magic == STORAGE_MAGIC, f"storage not initialized (magic {magic:#010x})"
    return record[KEY_OFFSET:KEY_OFFSET + KEY_SIZE]


class TestTrustedInputKeyPersistence:

    def test_first_boot_generates(self, client: RaggerClient):
        """Produces the NVRAM image the next test loads, written on teardown."""
        prevtx, index, _ = prevout_of("pkh-1to1.psbt")

        token = bytes(client.app.getTrustedInput(prevtx, index)["value"])
        assert len(token) == TRUSTED_INPUT_SIZE + 8

    @pytest.mark.nvram_reload
    def test_second_boot_reuses_the_key(self, client: RaggerClient):
        """The restored key is the one still in use, so it was not rewritten."""
        key = persisted_key()
        assert key != bytes(KEY_SIZE), "persisted key is all zero"

        prevtx, index, _ = prevout_of("pkh-1to1.psbt")
        token = bytes(client.app.getTrustedInput(prevtx, index)["value"])
        body, tag = token[:TRUSTED_INPUT_SIZE], token[TRUSTED_INPUT_SIZE:]

        # The token carries a fresh nonce each call, so tags cannot be compared
        # directly across boots - recompute one under the persisted key instead.
        expected = hmac.new(key, body, sha256).digest()[:8]
        assert tag == expected, "second boot is signing under a different key"
