"""Tests for INS_GET_MASTER_FINGERPRINT (0xd0) APDU.

The master fingerprint is the first 4 bytes of RIPEMD160(SHA256(compressed_master_pubkey)).
The firmware computes it via the os_perso_get_master_key_identifier() OS syscall,
which does NOT require the APPLICATION_FLAG_DERIVE_MASTER permission.

The test mnemonic used by Speculos (configured in conftest.py) is:
  "glory promote mansion idle axis finger extra february uncover one
   trip resource lawn turtle enact monster seven myth punch hobby
   comfort wild raise skin"

Its expected master fingerprint is f5acc2fd (visible in all test PSBT key origins).
"""

from ragger_bitcoin import RaggerClient

# Expected master fingerprint for the test mnemonic, pre-computed via BIP-32:
#   seed = PBKDF2("glory promote mansion...", "mnemonic", 2048, SHA-512)
#   master_secret = HMAC-SHA512("Bitcoin seed", seed)[:32]
#   master_pubkey = secp256k1_point(master_secret)
#   fingerprint = RIPEMD160(SHA256(compress(master_pubkey)))[:4]
EXPECTED_MASTER_FPR = bytes.fromhex("f5acc2fd")


def test_get_master_fingerprint(client: RaggerClient):
    """Test that INS_GET_MASTER_FINGERPRINT returns the correct 4-byte fingerprint."""

    fpr = client.get_master_fingerprint()

    assert isinstance(fpr, bytes), "Fingerprint should be bytes"
    assert len(fpr) == 4, f"Fingerprint should be 4 bytes, got {len(fpr)}"
    assert fpr == EXPECTED_MASTER_FPR, (
        f"Expected master fingerprint {EXPECTED_MASTER_FPR.hex()}, "
        f"got {fpr.hex()}"
    )


def test_get_master_fingerprint_consistency(client: RaggerClient):
    """Test that calling GET_MASTER_FINGERPRINT twice returns the same result."""

    fpr1 = client.get_master_fingerprint()
    fpr2 = client.get_master_fingerprint()

    assert fpr1 == fpr2, (
        f"Master fingerprint should be deterministic: "
        f"first call returned {fpr1.hex()}, second returned {fpr2.hex()}"
    )


def test_get_master_fingerprint_raw_apdu(client: RaggerClient):
    """Test the raw APDU directly, bypassing any client wrapper.

    Sends CLA=0xE0 INS=0xD0 P1=0x00 P2=0x00 Lc=0x00 and verifies
    the response is exactly 4 bytes.
    """
    apdu = bytearray([0xe0, 0xd0, 0x00, 0x00, 0x00])
    response = client.app.dongle.exchange(apdu)

    assert len(response) == 4, (
        f"Expected 4-byte response, got {len(response)} bytes: {response.hex()}"
    )
    assert bytes(response) == EXPECTED_MASTER_FPR
