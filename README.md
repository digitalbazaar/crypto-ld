# Cryptographic Key Pair Library for Linked Data _(crypto-ld)_

[![Build Status](https://travis-ci.org/digitalbazaar/crypto-ld.png?branch=master)](https://travis-ci.org/digitalbazaar/crypto-ld)

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

### Supported Key Types

This library provides general Linked Data cryptographic key generation 
functionality, but does not support any individual key type by default.

To use it, you must [install individual driver libraries](#usage) for each 
cryptographic key type. The following libraries are currently supported.

| Type        | Crypto Suite | Library | Usage |
|-------------|--------------|---------|-------|
| `ed25519`   | [Ed25519VerificationKey2018](https://w3c-ccg.github.io/ld-cryptosuite-registry/#ed25519) | [`ed25519-key-pair`](https://github.com/digitalbazaar/ed25519-key-pair) | Signatures, VCs, zCaps, DIDAuth |
| `secp256k1` | [EcdsaSecp256k1VerificationKey2019](https://w3c-ccg.github.io/ld-cryptosuite-registry/#secp256k1) | [`secp256k1-key-pair`](https://github.com/digitalbazaar/secp256k1-key-pair/) | Signatures, VCs, zCaps, DIDAuth, HD Wallets |
| `rsa`       | [RsaSignature2018](https://w3c-ccg.github.io/ld-cryptosuite-registry/#rsasignature2018) | [`rsa-key-pair`](https://github.com/digitalbazaar/rsa-key-pair) | Legacy/interop signatures and use cases |
| `x25519`    | X25519KeyAgreementKey2019 | [`x25519-key-pair`](https://github.com/digitalbazaar/x25519-key-pair) | [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) key agreement, JWE/CWE encryption with [`minimal-cipher`](https://github.com/digitalbazaar/minimal-cipher) |  

See also (related specs):

* [Linked Data Cryptographic Suite Registry](https://w3c-ccg.github.io/ld-cryptosuite-registry/)
* [Linked Data Proofs 1.0](https://w3c-dvcg.github.io/ld-proofs/)

#### Choosing a Key Type

For digital signatures using the 
[`jsonld-signatures`](https://github.com/digitalbazaar/jsonld-signatures), 
signing of Verifiable Credentials using [`vc-js`](https://github.com/digitalbazaar/vc-js),
authorization capabilities, and DIDAuth operations:

* Prefer **Ed25519** type keys, by default.
* Use **EcdsaSepc256k1** keys if your use case requires it (for example, if 
  you're developing for a Bitcoin-based or Ethereum-based ledger), or if you
  require Hierarchical Deterministic (HD) wallet functionality. 
* Only use RSA keys when interfacing with legacy systems that require them.
  
For key agreement protocols for encryption operations:

* Use **Curve25519** with the [`minimal-cipher`](https://github.com/digitalbazaar/minimal-cipher)
  library.

## Security

As with most security- and cryptography-related tools, the overall security of
your system will largely depend on your design decisions.

## Install

- Node.js 10.12.0+ is required.

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

For example, to use this library with only the `ed25519` key type:

```js
import {CryptoLD} from 'crypto-ld';
const cryptoLd = new CryptoLD();
import Ed25519 from 'ed25519-key-pair';

cryptoLd.use(Ed25519);

// With only one key type installed, you do not need to specify key type for
// most operations
const keyPair = await cryptoLd.generate(); // generates an ed25519 key pair
```

To use the library with all supported key types:

```js
import Ed25519 from 'ed25519-key-pair';
import RSA from 'rsa-key-pair';
import Secp256k1 from 'secp256k1-key-pair';
import X25519 from 'x25519-key-pair';

import {CryptoLD} from 'crypto-ld';
const cryptoLd = new CryptoLD();

cryptoLd.use(Ed25519); // ed25519 type
cryptoLd.use(RSA); // rsa type
cryptoLd.use(Secp256k1); // secp256k1 type
cryptoLd.use(X25519); // x25519 type

// When using multiple key types, you'll need to specify type when generating
const edKeyPair = await cryptoLd.generate({type: 'ed25519'});
const rsaKeyPair = await cryptoLd.generate({type: 'rsa'});
```

### Generating a new public/private key pair

To generate a new public/private key pair: `cryptoLd.generate(options)`:

* `{string} [type]` Optional if only one key type is installed, required otherwise. 
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

To export just the public key of a pair - `exportPublic()`:

```js
await keyPair.export({publicKey: true});
// ->
{ 
  id: 'did:ex:123#z6MkumafR1duPR5FZgbVu8nzX3VyhULoXNpq9rpjhfaiMQmx',
  controller: 'did:ex:123',
  type: 'Ed25519VerificationKey2018',
  publicKeyBase58: 'GKKcpmPU3sanTBkoDZq9fwwysu4x7VaUTquosPchSBza'
}
*/
```

#### Exporting the full public-private key pair

To export the full key pair, including private key (warning: this should be a
carefully considered operation, best left to dedicated Key Management Systems):

```js
await keyPair.export({publicKey: true, privateKey: true});
// ->
{
  id: 'did:ex:123#z6Mks8wJbzhWdmkQZgw7z2qHwaxPVnFsFmEZSXzGkLkvhMvL',
  controller: 'did:ex:123',
  type: 'Ed25519VerificationKey2018',
  publicKeyBase58: 'DggG1kT5JEFwTC6RJTsT6VQPgCz1qszCkX5Lv4nun98x',
  privateKeyBase58: 'sSicNq6YBSzafzYDAcuduRmdHtnrZRJ7CbvjzdQhC45ewwvQeuqbM2dNwS9RCf6buUJGu6N3rBy6oLSpMwha8tc'
}
```

#### Generating and verifying key fingerprint

To generate a fingerprint:

```js
keyPair.fingerprint();
// ->
'z6Mks8wJbzhWdmkQZgw7z2qHwaxPVnFsFmEZSXzGkLkvhMvL'
```

To verify a fingerprint:

```js
keyPair.verifyFingerprint('z6Mks8wJbzhWdmkQZgw7z2qHwaxPVnFsFmEZSXzGkLkvhMvL');
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
const keyPair = cryptoLd.generate({type: 'ed25519'});

const {sign} = keyPair.signer();

const data = 'test data to sign';
const signatureValue = await sign({data});
```

#### Creating a verifier function

In order to verify a cryptographic signature, you need to create a `verify`
function, and then invoke it (passing it the data to verify, and the signature).

```js
const keyPair = cryptoLd.generate({type: 'ed25519'});

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
