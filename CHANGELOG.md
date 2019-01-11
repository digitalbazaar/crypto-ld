# crypto-ld ChangeLog

## 2.0.0 - 2019-xx-xx

### Fixed
- Specify published files.

### Changed
- **BREAKING** `Ed25519KeyPair` now uses `publicKeyBase58` and
  `privateKeyBase58` attributes, instead of `publicKeyBase` and
  `privateKeyBase`
- **BREAKING** Changed signature of `LDKeyPair.from()` (one `options` param
  instead of a separate `data` and `options`)
- Removed ursa support.
  - Node.js >= 10.12.0: use generateKeyPair().
  - Earlier Node.js and browsers: use forge.
  - **NOTE**: Newer Node.js versions are *much* faster at RSA key generation vs
    the forge fallback. It is highly recommended to use a newer Node.js.
- Switch from chloride to sodium-universal.

### Added
- Added `controller` attribute (to use instead of the deprecated `owner`)
- Added `sign()` and `verify()` factory functions for use with
  `jsonld-signatures`
- Add Karma browser testing support.

## 1.0.0 - 2018-11-08

- Change keyType to type (do match DID Doc usage), add key owner
- Initial NPM release

## 0.1.0 - 2018-10-17

- Moved LDKeyPair code from `did-io`
