# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [2.4.11] - 2026-04-13

### Added

- `INS_GET_MASTER_FINGERPRINT` to obtain the master key fingerprint

### Modified

- Derivation Path Hardening applied to `bitcoin_testnet_legacy`

## [2.4.10] - 2026-02-19

### Modified

- Derivation Path Hardening:
    - `HAVE_APPLICATION_FLAG_DERIVE_MASTER` is removed for all coins except Bitcoin Legacy and Bitcoin Test Legacy
    - BIP-32 derivation paths are enforced using wildcard syntax (`m/*/<COIN_TYPE>`), with a few exceptions for Bitcoin forks
- Ticker moved on the right.

## [2.4.9] - 2025-09-08

### Modified

- Apex P porting
- Nano S support removal

## [2.4.8] - 2025-08-08

### Fixed

- Adaptation to IO revamp changes.

## [2.1.0] - 2022-09-15

### Modified

Rename the "bitcoin" target to "bitcoin_legacy".

## [1.6.6] - 2022-05-11

Technical release for the deployment of the legacy app.

## [1.6.2](https://github.com/ledgerhq/app-bitcoin/compare/1.6.1...1.6.2) - 2021-06-24

### Fixed

- Fixed Qtum derivation for Native Segwit accounts
- Revert Firo's COINID to zcoin
## [1.6.1](https://github.com/ledgerhq/app-bitcoin/compare/1.6.0...1.6.1) - 2021-05-31

### Modified

- Zcoin becomes Firo
## [1.6.0](https://github.com/ledgerhq/app-bitcoin/compare/1.5.6...1.6.0) - 2021-04-30

### Added

- Better python tests
- Add wallet ID feature on Nano X
## [1.5.6](https://github.com/ledgerhq/app-bitcoin/compare/1.5.5...1.5.6) - 2021-03-25

### Added

- Compatibility with Nano S 2.0.0 firmware
- Message signing displays the whole message hash instead of truncating it

## [1.5.5](https://github.com/ledgerhq/app-bitcoin/compare/1.5.4...1.5.5) - 2021-01-06

### Added

- Support for Native Segwit on VertCoin

## [1.5.4](https://github.com/ledgerhq/app-bitcoin/compare/1.5.3...1.5.4) - 2021-01-06

### Fixed

- Remove a change that was breaking swap feature when used with older apps [#180](https://github.com/LedgerHQ/app-bitcoin/pull/180)

### Added

- Tests and GitHub Actions CI

## [1.5.3](https://github.com/ledgerhq/app-bitcoin/compare/1.5.2...1.5.3) - 2020-12-11

### Fixed

- Fix pin validation check on Nano X

## [1.5.2](https://github.com/ledgerhq/app-bitcoin/compare/1.5.1...1.5.2) - 2020-12-10

### Added

- Changelog file

### Removed

- unused `prepare_full_output` and `btchip_bagl_confirm_full_output` functions removed

### Changed

- More errors, less THROWs
- Cleanup args parsing when called as a library

### Fixed

- Most compilation warnings fixed
- Ensure `os_lib_end` is called when errors are encountered in library mode
- Fix pin validation check
