# crypto-ld ChangeLog

## 2.0.0 - 2019-01-04

- Added `controller` attribute (to use instead of the deprecated `owner`)
- Added `sign()` and `verify()` factory functions for use with `jsonld-signatures`
- **BREAKING** `Ed25519KeyPair` now uses `publicKeyBase58` and `privateKeyBase58`
  attributes, instead of `publicKeyBase` and `privateKeyBase`
- **BREAKING** Changed signature of `LDKeyPair.from()` (one `options` param
  instead of a separate `data` and `options`)

## 1.0.0 - 2018-11-08

- Change keyType to type (do match DID Doc usage), add key owner
- Initial NPM release

## 0.1.0 - 2018-10-17

- Moved LDKeyPair code from `did-io`
