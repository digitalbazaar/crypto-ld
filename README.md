# Crypto LD (Linked Data) _(crypto-ld)_

[![Build Status](https://travis-ci.org/digitalbazaar/crypto-ld.png?branch=master)](https://travis-ci.org/digitalbazaar/crypto-ld)

> A Javascript library for cryptographic operations using Linked Data

## Table of Contents

- [Background](#background)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [API](#api-documentation)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

See also (related specs):

* [Linked Data Proofs 1.0](https://w3c-dvcg.github.io/ld-proofs/)
* [Linked Data Cryptographic Suite Registry](https://w3c-ccg.github.io/ld-cryptosuite-registry/)

### Supported Key Types

This library provides general Linked Data key generation functionality, but
does not support any individual key type by default.

To use it, you must install individual driver libraries for each cryptographic
key type. The following are currently supported:

* [Ed25519](https://w3c-ccg.github.io/ld-cryptosuite-registry/#ed25519) keys:
  [`ed25519key-pair` lib](https://github.com/digitalbazaar/ed25519-key-pair)
* [RSA](https://w3c-ccg.github.io/ld-cryptosuite-registry/#rsa) keys:
  [`rsa-pair` lib](https://github.com/digitalbazaar/rsa-key-pair)
* [EcdsaSecp256k1](https://w3c-dvcg.github.io/lds-ecdsa-secp256k1-2019/) keys: 
  [`secp256k1-key-pair`](https://github.com/digitalbazaar/secp256k1-key-pair/)
* Curve25519 keys:
  [`x25519-key-pair`](https://github.com/digitalbazaar/x25519-key-pair)

#### Choosing a Key Type

For digital signatures using the 
[`jsonld-signatures`](https://github.com/digitalbazaar/jsonld-signatures), 
signing of Verifiable Credentials using [`vc-js`](https://github.com/digitalbazaar/vc-js),
authorization capabilities, and DIDAuth operations:

* Prefer **Ed25519** type keys, by default.
* Use **EcdsaSepc256k1** keys if your use case requires it (for example, if 
  you're developing for a Bitcoin-based or Ethereum-based ledger), or if you
  require Hierarchical Deterministic (HD) wallet functionality. 
* You should only use RSA keys when interfacing with legacy systems that
  require them.
  
For key agreement protocols for encryption operations:

* Use **Curve25519** with the [`minimal-cipher`](https://github.com/digitalbazaar/minimal-cipher)
  library.

## Security

As with most security- and cryptography-related tools, the overall security of
your system will largely depend on your design decisions.

## Install

- Node.js 8.3+ required.
- Node.js 10.12.0+ is highly recommended due to RSA key generation speed.

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

```
const {cryptoLd} = require('crypto-ld');
cryptoLd.use(require('ed25519-key-pair');

// With only one key type installed, you do not need to specify key type for
// most operations
const keyPair = await cryptoLd.generate(); // generates an ed25519 key pair
```

To use the library with all supported key types:

```
const {cryptoLd} = require('crypto-ld');
cryptoLd.use(require('ed25519-key-pair')); // Ed25519VerificationKey2018 type
cryptoLd.use(require('rsa-key-pair')); // RsaVerificationKey2018 type
cryptoLd.use(require('secp256k1-key-pair')); // EcdsaSecp256k1VerificationKey2019 type
cryptoLd.use(require('x25519-key-pair')); // X25519KeyAgreementKey2019 type

// When using multiple key types, you'll need to specify type when generating
const rsaKeyPair = await cryptoLd.generate({type: 'RsaVerificationKey2018'});
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
const serializedKeyPair = await loadFromSomeStorage();

const keyPair = cryptoLd.from(serializedKeyPair);
```

Note that only installed key types are supported, if you try to create a
key pair via `from()` for an unsupported type, an error will be thrown.

### Common individual key pair operations

The full range of operations will depend on key type. Here are some common
operations supported by all key types.

#### Exporting the public key only

To export just the public key of a pair - `exportPublic()`:

```
await keyPair.exportPublic();
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

```
await keyPair.exportFull();
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

```
keyPair.fingerprint();
// ->
'z6Mks8wJbzhWdmkQZgw7z2qHwaxPVnFsFmEZSXzGkLkvhMvL'
```

To verify a fingerprint:

```
keyPair.verifyFingerprint('z6Mks8wJbzhWdmkQZgw7z2qHwaxPVnFsFmEZSXzGkLkvhMvL');
// ->
{ valid: true }
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
