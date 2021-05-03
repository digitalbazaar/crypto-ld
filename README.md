# Cryptographic Key Pair Library for Linked Data _(crypto-ld)_

[![Node.js CI](https://github.com/digitalbazaar/crypto-ld/workflows/Node.js%20CI/badge.svg)](https://github.com/digitalbazaar/crypto-ld/actions?query=workflow%3A%22Node.js+CI%22)
[![NPM Version](https://img.shields.io/npm/v/crypto-ld.svg?style=flat-square)](https://npm.im/crypto-ld)


> A Javascript library for generating and performing common operations on Linked Data cryptographic key pairs.

## Table of Contents

- [Background](#background)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

See also (related specs):

* [Linked Data Cryptographic Suite Registry](https://w3c-ccg.github.io/ld-cryptosuite-registry/)
* [Linked Data Proofs 1.0](https://w3c-ccg.github.io/ld-proofs/)

### Supported Key Types (`crypto-ld` versions `4+`)

This library provides general Linked Data cryptographic key generation 
functionality, but does not support any individual key type by default.

To use it, you must [install individual driver libraries](#usage) for each 
cryptographic key type. The following libraries are currently supported.

| Type        | Crypto Suite | Library | Usage |
|-------------|--------------|---------|-------|
| `Ed25519`   | **[Ed25519VerificationKey2020](https://w3c-ccg.github.io/lds-ed25519-2020/#ed25519verificationkey2020)** (recommended), [Ed25519VerificationKey2018](https://w3c-ccg.github.io/lds-ed25519-2018/#the-ed25519-key-format) (legacy) | **[`ed25519-verification-key-2020 >=1.0`](https://github.com/digitalbazaar/ed25519-verification-key-2020)** (recommended),  [`ed25519-verification-key-2018 >=2.0`](https://github.com/digitalbazaar/ed25519-verification-key-2018) (legacy) | Signatures, VCs, zCaps, DIDAuth |
| `X25519/Curve25519`    | X25519KeyAgreementKey2019 | [`x25519-key-agreement-key-2019 >=4.0`](https://github.com/digitalbazaar/x25519-key-agreement-key-2019) | [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) key agreement, JWE/CWE encryption with [`minimal-cipher`](https://github.com/digitalbazaar/minimal-cipher) |  
| `Secp256k1` | [EcdsaSecp256k1VerificationKey2019](https://w3c-ccg.github.io/ld-cryptosuite-registry/#secp256k1) | [`ecdsa-secp256k1-verification-key-2019`](https://github.com/digitalbazaar/ecdsa-secp256k1-verification-key-2019) | Signatures, VCs, zCaps, DIDAuth, HD Wallets |

### Legacy Supported Key Types (`crypto-ld` versions `<=3`)

In the previous version (v3.x) of `crypto-ld`, the RSA and Ed25519 suites were
bundled with `crypto-ld` (as opposed to residing in standalone packages).
For previous usage instructions of bundled RSA, Ed25519 and standalone
Curve25519/[`x25519-key-pair`](https://github.com/digitalbazaar/x25519-key-agreement-key-2019/tree/v3.1.0)
type keys, see the [README for `crypto-ld` v3.9](https://github.com/digitalbazaar/crypto-ld/tree/v3.9.0).

### Choosing a Key Type

For digital signatures using the 
[`jsonld-signatures`](https://github.com/digitalbazaar/jsonld-signatures), 
signing of Verifiable Credentials using [`vc-js`](https://github.com/digitalbazaar/vc-js),
authorization capabilities, and DIDAuth operations:

* Prefer **Ed25519VerificationKey2020** type keys, by default.
* Use **EcdsaSepc256k1** keys if your use case requires it (for example, if 
  you're developing for a Bitcoin-based or Ethereum-based ledger), or if you
  require Hierarchical Deterministic (HD) wallet functionality. 
  
For key agreement protocols for encryption operations:

* Use **Curve25519** with the [`minimal-cipher`](https://github.com/digitalbazaar/minimal-cipher)
  library.

## Security

As with most security- and cryptography-related tools, the overall security of
your system will largely depend on your design decisions.

## Install

- Node.js 12.0+ is required.

To install locally (for development):

```
git clone https://github.com/digitalbazaar/crypto-ld.git
cd crypto-ld
npm install
```

## Usage

### Installing Support for Key Types

In order to use this library, you will need to import and install driver
libraries for key types you'll be working with via the `use()` method.

To use the library with one or more supported suites:

```js
import {Ed25519VerificationKey2020} from '@digitalbazaar/ed25519-verification-key-2020';
import {X25519KeyAgreementKey2020} from '@digitalbazaar/x25519-key-agreement-key-2020';

import {CryptoLD} from 'crypto-ld';
const cryptoLd = new CryptoLD();

cryptoLd.use(Ed25519VerificationKey2020);
cryptoLd.use(X25519KeyAgreementKey2020);

const edKeyPair = await cryptoLd.generate({type: 'Ed25519VerificationKey2020'});
```

### Generating a new public/private key pair

To generate a new public/private key pair: `cryptoLd.generate(options)`:

* `{string} [type]` Suite name, required. 
* `{string} [controller]` Optional controller URI or DID to initialize the
  generated key. (This will also init the key id.) 
* `{string} [seed]` Optional deterministic seed value (only supported by some
  key types, such as `ed25519`) from which to generate the key.

### Importing a key pair from storage

To create an instance of a public/private key pair from data imported from
storage, use `cryptoLd.from()`:

```js
const serializedKeyPair = { ... };

const keyPair = await cryptoLd.from(serializedKeyPair);
```

Note that only installed key types are supported, if you try to create a
key pair via `from()` for an unsupported type, an error will be thrown.

### Common individual key pair operations

The full range of operations will depend on key type. Here are some common
operations supported by all key types.

#### Exporting the public key only

To export just the public key of a pair - use `export()`:

```js
keyPair.export({publicKey: true});
// ->
{
  type: 'Ed25519VerificationKey2020',
  id: 'did:example:1234#z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3',
  controller: 'did:example:1234',
  publicKeyMultibase: 'zEYJrMxWigf9boyeJMTRN4Ern8DJMoCXaLK77pzQmxVjf'
}
```

#### Exporting the full public-private key pair

To export the full key pair, including private key (warning: this should be a
carefully considered operation, best left to dedicated Key Management Systems):

```js
keyPair.export({publicKey: true, privateKey: true});
// ->
{
  type: 'Ed25519VerificationKey2020',
  id: 'did:example:1234#z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3',
  controller: 'did:example:1234',
  publicKeyMultibase: 'zEYJrMxWigf9boyeJMTRN4Ern8DJMoCXaLK77pzQmxVjf',
  privateKeyMultibase: 'z4E7Q4neNHwv3pXUNzUjzc6TTYspqn9Aw6vakpRKpbVrCzwKWD4hQDHnxuhfrTaMjnR8BTp9NeUvJiwJoSUM6xHAZ'
}
```

#### Generating and verifying key fingerprint

To generate a fingerprint:

```js
keyPair.fingerprint();
// ->
'z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3'
```

To verify a fingerprint:

```js
keyPair.verifyFingerprint({
  fingerprint: 'z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3'
});
// ->
{ valid: true }
```

### Operations on signature-related key pairs

For key pairs that are related to signature and verification (that extend from
the `LDVerifierKeyPair` class), two additional operations must be supported:

#### Creating a signer function

In order to perform a cryptographic signature, you need to create a `sign`
function, and then invoke it.

```js
const keyPair = await cryptoLd.generate({type: 'Ed25519VerificationKey2020'});

const {sign} = keyPair.signer();

const data = 'test data to sign';
const signatureValue = await sign({data});
```

#### Creating a verifier function

In order to verify a cryptographic signature, you need to create a `verify`
function, and then invoke it (passing it the data to verify, and the signature).

```js
const keyPair = await cryptoLd.generate({type: 'Ed25519VerificationKey2020'});

const {verify} = keyPair.verifier();

const {valid} = await verify({data, signature});
```

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[New BSD License (3-clause)](LICENSE) © Digital Bazaar
