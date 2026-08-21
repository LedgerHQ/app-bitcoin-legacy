from ragger.navigator import Navigator
from ragger.firmware import Firmware
from ragger_bitcoin import RaggerClient
from ragger_bitcoin.ragger_instructions import Instructions
from ragger.navigator import NavInsID

import pytest
from ragger.error import ExceptionRAPDU


def pubkey_instruction_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Approve")
    else:
        instructions.address_confirm()
        instructions.same_request("Address", NavInsID.USE_CASE_REVIEW_TAP,
                                  NavInsID.USE_CASE_STATUS_DISMISS)
    return instructions


def pubkey_instruction_warning_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Approve")
        instructions.same_request("Approve")
    else:
        instructions.new_request("Unusual", NavInsID.USE_CASE_CHOICE_CONFIRM,
                                 NavInsID.USE_CASE_CHOICE_CONFIRM)
        instructions.same_request("Confirm",
                                  NavInsID.SWIPE_CENTER_TO_LEFT,
                                  NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM)
        instructions.same_request("Address", NavInsID.USE_CASE_REVIEW_TAP,
                                  NavInsID.USE_CASE_STATUS_DISMISS)
    return instructions


def test_get_public_key(navigator: Navigator, firmware: Firmware,
                        client: RaggerClient, test_name: str):
    testcases = {
        "m/84'/1'/2'/0/10":
        "tpubDG9YpSUwScWJBBSrhnAT47NcT4NZGLcY18cpkaiWHnkUCi19EtCh8Heeox268NaFF6o56nVeSXuTyK6jpzTvV1h68Kr3edA8AZp27MiLUNt"}
    for path, pubkey in testcases.items():
        assert pubkey == client.get_extended_pubkey(
            path=path,
            display=True,
            navigator=navigator,
            instructions=pubkey_instruction_approve(firmware),
            testname=f"{test_name}_{path}"
        )
    testcases = {
        "m/44'/1'/0'": "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT",
        "m/44'/1'/10'": "tpubDCwYjpDhUdPGp21gSpVay2QPJVh6WNySWMXPhbcu1DsxH31dF7mY18oibbu5RxCLBc1Szerjscuc3D5HyvfYqfRvc9mesewnFqGmPjney4d",
        "m/44'/1'/2'/1/42": "tpubDGF9YgHKv6qh777rcqVhpmDrbNzgophJM9ec7nHiSfrbss7fVBXoqhmZfohmJSvhNakDHAspPHjVVNL657tLbmTXvSeGev2vj5kzjMaeupT",
        "m/48'/1'/4'/1'/0/7": "tpubDK8WPFx4WJo1R9mEL7Wq325wBiXvkAe8ipgb9Q1QBDTDUD2YeCfutWtzY88NPokZqJyRPKHLGwTNLT7jBG59aC6VH8q47LDGQitPB6tX2d7",
        "m/49'/1'/1'/1/3": "tpubDGnetmJDCL18TyaaoyRAYbkSE9wbHktSdTS4mfsR6inC8c2r6TjdBt3wkqEQhHYPtXpa46xpxDaCXU2PRNUGVvDzAHPG6hHRavYbwAGfnFr",
        "m/86'/1'/4'/1/12": "tpubDHTZ815MvTaRmo6Qg1rnU6TEU4ZkWyA56jA1UgpmMcBGomnSsyo34EZLoctzZY9MTJ6j7bhccceUeXZZLxZj5vgkVMYfcZ7DNPsyRdFpS3f",
    }

    for path, pubkey in testcases.items():
        assert pubkey == client.get_extended_pubkey(
            path=path,
            display=True,
            navigator=navigator,
            instructions=pubkey_instruction_warning_approve(firmware),
            testname=f"{test_name}_{path}"
        )


def test_get_public_key_root_rejected(client: RaggerClient):
    """Test that getWalletPublicKey with an empty path (root level m/) is rejected.

    With derivation path hardening, the firmware should not allow
    derivation at the master level (depth 0) via getWalletPublicKey.
    This relies on the OS-level PATH_APP_LOAD_PARAMS enforcement
    (unless HAVE_APPLICATION_FLAG_DERIVE_MASTER is set).
    """
    with pytest.raises(ExceptionRAPDU) as exc_info:
        # Empty path = root level derivation, should be rejected by the OS
        client.app.getWalletPublicKey("")
    # The ragger backend raises ExceptionRAPDU (with .status) before btchip
    # can wrap it as BTChipException. The OS rejection surfaces as:
    #   0x6982 = SECURITY_STATUS_NOT_SATISFIED (direct OS rejection)
    #   0x6985 = CONDITIONS_OF_USE_NOT_SATISFIED
    #   0x6f00 = SW_TECHNICAL_PROBLEM (bip32_derive fails → get_public_key
    #           returns -1 → handler returns SW_TECHNICAL_PROBLEM)
    assert exc_info.value.status in (0x6982, 0x6985, 0x6f00), (
        f"Expected a security/path rejection error, got SW=0x{exc_info.value.status:04X}"
    )


def test_get_public_key_depth2_works(navigator: Navigator, firmware: Firmware,
                                     client: RaggerClient, test_name: str):
    """Test that getWalletPublicKey at depth >= 2 matching PATH_APP_LOAD_PARAMS works.

    With PATH_APP_LOAD_PARAMS = "*/1'", the OS requires at least depth 2
    where the second component is 1' (testnet coin_type). A depth-1 path
    like m/44' alone does NOT match the "*/1'" prefix.
    """
    # m/44'/1' matches "*/1'" — purpose=44' (wildcard), coin_type=1' (testnet)
    result = client.app.getWalletPublicKey("44'/1'")

    # Should return a valid public key (65 bytes uncompressed) and chaincode (32 bytes)
    assert len(result['publicKey']) == 65, (
        f"Expected 65-byte uncompressed pubkey, got {len(result['publicKey'])} bytes"
    )
    assert result['publicKey'][0] == 0x04, (
        f"Uncompressed pubkey should start with 0x04, got 0x{result['publicKey'][0]:02x}"
    )
    assert len(result['chainCode']) == 32, (
        f"Expected 32-byte chaincode, got {len(result['chainCode'])} bytes"
    )
    assert len(result['address']) > 0, "Address should not be empty"
