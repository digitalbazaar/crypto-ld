# crypto-ld ChangeLog

## 6.0.0 - 2021-05-05

### Changed
- **BREAKING**: `.from()` now routs to `.fromKeyDocument()` if the serialized
  key object has a `@context`. This update is to make for more secure behavior
  when creating key pair instances from "untrusted" key objects (say, fetched
  from the web etc).

## 5.1.0 - 2021-04-01

### Added
- Implement `CryptoLD.fromKeyId` API.
- Implement `LDKeyPair.fromKeyDocument` API.
- Add support for revoked keys.

## 5.0.0 - 2021-03-16

### Changed
- **BREAKING**: Remove `LDVerifierKeyPair` subclass. Fold `signer()` and
  `verifier()` methods into parent `LDKeyPair` class.
- **BREAKING**: `export()` is now a sync function (no reason for it to be
  async).
- **BREAKING**: Remove `keyPair.addPrivateKey()` and `keyPair.addPublicKey()`.
  Subclasses will just need to override `export()` directly.

### Upgrading from v4.x
The breaking changes in v5 do not affect any application code, they only affect
key pair plugins such as
https://github.com/digitalbazaar/ed25519-verification-key-2020.
No changes necessary in application code upgrading from `v5` from `v4`.

## 4.0.3 - 2020-11-25

### Changed
- Publish package.

## 4.0.2 - 2020-08-01

### Changed
- Fix `use()` suite usage.

## 4.0.1 - 2020-08-01

### Changed
- Removed unused `sodium-native` dependency.

## 4.0.0 - 2020-08-01

### Changed
- Implement chai-like `.use()` API for installing and specifying individual key
  types.
- **BREAKING**: Extracted bundled Ed25519 and RSA key suites to their own
  libraries.
- **BREAKING**: Remove deprecated `.owner` instance property
- **BREAKING**: Remove deprecated `.passphrase` instance property, and the
  `encrypt()` and `decrypt()` methods (these are no longer used).
- **BREAKING**: Remove deprecated/unused `publicKey` and `privateKey`
  properties.
- **BREAKING**: Rename `.publicNode()` to `.export({publicKey: true})`.
- **BREAKING**: `.export()` now requires explicitly stating whether you're
  exporting public or private key material.
- **BREAKING**: Changed `verifyFingerprint()` to used named params.
- **BREAKING**: Changed `addPublicKey()` and `addPrivateKey()` to used named
  params.

### 4.0.0 - Purpose

The previous design (`v3.7` and earlier) bundled two key types with this
library (RSA and Ed25519), which resulted in extraneous code and bundle size
for projects that only used one of them (or used some other suite). The
decision was made to extract those bundled suites to their own repositories,
and to add a builder-style `.use()` API to `crypto-ld` so that client code
could select just the suites they needed.

Since this was a comprehensive breaking change in usage, this also gave an
opportunity to clean up and streamline the existing API, change function
signatures to be consistent (for example, to consistently used named
parameters), and to remove deprecated and unused APIs and properties.

### Upgrading from v3.7.0

Since this is a comprehensive breaking change, you will need to audit and change
pretty much all usage of `crypto-ld` and compatible key pairs. Specifically:

* Ed25519 and RSA keys are no longer imported from `crypto-ld`, they'll need to
  be imported from their own packages.
* Since key suites have been decoupled from `crypto-ld`, it means that this
  library should only be used when a project is using _multiple_ key suites.
  If you're just using a single suite, then you can use that suite directly,
  without `crypto-ld`.
* Most function param signatures have been changed to use `{}` style named
  params.

## 3.7.0 - 2019-09-06

### Added
- Add support for Node 12 Ed25519 generate, sign, and verify.
- Make `sodium-native` an optional dependency.

## 3.6.0 - 2019-08-06

### Added
- Add `LDKeyPair.fromFingerprint()` to create an Ed25519KeyPair instance
  from a fingerprint (for use with `did:key` method code).

## 3.5.3 - 2019-07-16

### Fixed
- Use base64url-universal@1.0.1 which properly specifies the Node.js engine.

## 3.5.2 - 2019-04-16

### Fixed
- Fix incorrectly formatted engine tag in package file.

## 3.5.1 - 2019-04-09

### Fixed
- The `util.base58PublicKeyFingerprint` was released in error. It has been
  replaced by the `Ed25519KeyPair.fingerprintFromPublicKey` API contained
  in this release.

## 3.5.0 - 2019-04-08

### Added
- Add `util.base58PublicKeyFingerprint` helper for computing public key
  fingerprints. NOTE: this API was released in error, see release 3.5.1.

## 3.4.1 - 2019-03-27

### Fixed
- Fix Ed25519 fingerprint generation when running in the browser.

## 3.4.0 - 2019-02-26

### Added
- Enable use of a `seed` to generate deterministic Ed25519 keys.

## 3.3.0 - 2019-02-21

### Changed
- Improve error handling related to the decoding of key material in
  `Ed25519KeyPair`. This is helpful when dealing with key material that may
  be provided via command line or web UI.

## 3.2.0 - 2019-02-19

### Changed
- Remove `sodium-universal` dependency to reduce the size of the browser bundle.
- Ed25519 operations in Node.js use `sodium-native` APIs.
- Ed25519 operations in the browser use `forge` APIs.
- Use `base64url-universal` which eliminates the need for a `Buffer` polyfill
  when this module is used in the browser.

## 3.1.0 - 2019-02-18

### Changed
- Use forge@0.8.0. The new `rsa.generateKeyPair` API automatically uses
  native implementation when available in nodejs >= 10.12.0.

## 3.0.0 - 2019-01-30

### Changed
- **BREAKING**: Make key fingerprints conform to the latest multibase/multicodec
  specification. The fingerprints generated by 2.x and 3.x are different due
  to encoding changes.
- **BREAKING**: The only exports for this module are the three key classes:
  `LDKeyPair`, `Ed25519KeyPair`, and `RSAKeyPair`.

## 2.0.1 - 2019-01-24

### Fixed
- No need to bring in `util` in browser environment.

## 2.0.0 - 2019-01-16

### Fixed
- Specify published files.

### Changed
- **BREAKING**: `Ed25519KeyPair` now uses `publicKeyBase58` and
  `privateKeyBase58` attributes, instead of `publicKeyBase` and
  `privateKeyBase`
- **BREAKING**: Changed signature of `LDKeyPair.from()` (one `options` param
  instead of a separate `data` and `options`)
- Removed `ursa` support.
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
