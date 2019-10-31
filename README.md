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

As a developer, in order to use this library, you will need to make the 
following decisions, constrained by your use case:

1. [Which key type](#choosing-key-type) and suite to use?
2. What IDs will you give your keys? We recommend the following pattern:
    `<did or url>#<key fingerprint>`. (See Exporting Key Pair section below
    for an example of this.)
3. (Not required, but highly recommended) What is your [Private Key Storage](#private-key-storage) 
    strategy? (KMS, file system, secure wallet)

### Supported Key Types

This library supports the following key types (used primarily for the purpose
of digital signatures):

* [Ed25519](https://w3c-ccg.github.io/ld-cryptosuite-registry/#ed25519)
* [RSA](https://w3c-ccg.github.io/ld-cryptosuite-registry/#rsa)

These key pairs can be used for general purpose digital signatures using the 
[`jsonld-signatures`](https://github.com/digitalbazaar/jsonld-signatures), 
signing of Verifiable Credentials using [`vc-js`](https://github.com/digitalbazaar/vc-js),
and other purposes.

Additional key types are available (using the same API as this library) at the
following repos:

* [EcdsaSecp256k1](https://w3c-dvcg.github.io/lds-ecdsa-secp256k1-2019/) at 
    [`secp256k1-key-pair`](https://github.com/digitalbazaar/secp256k1-key-pair/)
* Curve25519 at [`x25519-key-pair`](https://github.com/digitalbazaar/x25519-key-pair)
  (for use with [`minimal-cipher`](https://github.com/digitalbazaar/minimal-cipher))

#### Choosing Key Type

TODO: Add design considerations for choosing key types / cryptographic 
algorithms for various purposes. For now:

* Use **Ed25519** keys if you can
* Use **EcdsaSepc256k1** keys if you must (for example, if you're developing for 
  a Bitcoin-based or Ethereum-based ledger) 
* You _can_ use RSA keys to sign, if your use case requires it.
* Use **Curve25519** for key agreement protocols.

#### Private Key Storage

Where to store the private keys?

TODO: Add a brief discussion of where to store the private keys. Point to
several recommended Wallet or KMS libraries.

Use `await keyPair.export()`

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

### Generating a new key pair

Ed25519:

```js
const {Ed25519KeyPair} = require('crypto-ld');

const keyPair = await Ed25519KeyPair.generate();
```

RSA:

```js
const {RSAKeyPair} = require('crypto-ld');

const keyPair = await RSAKeyPair.generate();
```

### Exporting a public/private key pair

```js
const edKeyPair = await Ed25519KeyPair.generate();
edKeyPair.id = 'did:ex:123#' + edKeyPair.fingerprint();

console.log(await edKeyPair.export())
/* ->
{ 
  id: 'did:ex:123#z6MkumafR1duPR5FZgbVu8nzX3VyhULoXNpq9rpjhfaiMQmx',
  type: 'Ed25519VerificationKey2018',
  publicKeyBase58: 'GKKcpmPU3sanTBkoDZq9fwwysu4x7VaUTquosPchSBza',
  privateKeyBase58:
   '3cEzNVGdLoujfhWXqrbo1FgYy9GHA5GXYvB4KixHVuQoRbWbHTJP7XTkj6LqXeiFhw79v85E4wjPQc8WcdyzntcA' 
}
*/

```

### Importing a key pair from storage

If you know what type of key you're expecting, use its appropriate class:

```js
const serializedKeyPair = JSON.stringify(await keyPair.export());
// later
const keyPair = await Ed25519KeyPair.from(JSON.parse(serializedKeyPair));
```

If you do not know which key type to expect, `LDKeyPair.from()` will route
based on type:

```js
const {LDKeyPair} = require('crypto-ld');

// serializedKeyPair contains a serialized Ed25519KeyPair
const keyPair = await LDKeyPair.from(JSON.parse(serializedKeyPair));
```

## API Documentation

See [LD Key Pair Documentation](/docs/LDKeyPair.md)

See [Ed25519 Key Pair Documentation](/docs/Ed25519KeyPair.md)

See [RSA Key Pair Documentation](/docs/RSAKeyPair.md)

See [Type Documentation](/docs/index.md)

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
