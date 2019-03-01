## Usage

<a name="Ed25519KeyPair"></a>

## Ed25519KeyPair
**Kind**: global class  

* [Ed25519KeyPair](#Ed25519KeyPair)
    * [new Ed25519KeyPair(options)](#new_Ed25519KeyPair_new)
    * _instance_
        * [.publicKey](#Ed25519KeyPair+publicKey) ⇒ <code>string</code>
        * [.privateKey](#Ed25519KeyPair+privateKey) ⇒ <code>string</code>
        * [.signer()](#Ed25519KeyPair+signer) ⇒ <code>Object</code>
        * [.verifier()](#Ed25519KeyPair+verifier) ⇒ <code>Object</code>
        * [.addEncodedPublicKey(publicKeyNode)](#Ed25519KeyPair+addEncodedPublicKey) ⇒ <code>Object</code>
        * [.addEncryptedPrivateKey(keyNode)](#Ed25519KeyPair+addEncryptedPrivateKey) ⇒ <code>Object</code>
        * [.encrypt(privateKey, password)](#Ed25519KeyPair+encrypt) ⇒ <code>Promise.&lt;JWE&gt;</code>
        * [.decrypt(jwe, password)](#Ed25519KeyPair+decrypt) ⇒ <code>Object</code>
        * [.fingerprint()](#Ed25519KeyPair+fingerprint) ⇒ <code>string</code>
        * [.verifyFingerprint(fingerprint)](#Ed25519KeyPair+verifyFingerprint) ⇒ <code>Object</code>
    * _static_
        * [.generate([options])](#Ed25519KeyPair.generate) ⇒ [<code>Promise.&lt;Ed25519KeyPair&gt;</code>](#Ed25519KeyPair)
        * [.from(options)](#Ed25519KeyPair.from) ⇒ [<code>Ed25519KeyPair</code>](#Ed25519KeyPair)

<a name="new_Ed25519KeyPair_new"></a>

### new Ed25519KeyPair(options)
An implementation of
[Ed25519 Signature 2018](https://w3c-dvcg.github.io/lds-ed25519-2018/)
for
[jsonld-signatures.](https://github.com/digitalbazaar/jsonld-signatures)


| Param | Type | Description |
| --- | --- | --- |
| options | <code>KeyPairOptions</code> | Base58 keys plus other options most follow [KeyPairOptions](./index.md#KeyPairOptions). |
| options.publicKeyBase58 | <code>string</code> | Base58 encoded Public Key unencoded is 32-bytes. |
| options.privateKeyBase58 | <code>string</code> | Base58 Private Key unencoded is 64-bytes. |

**Example**  
```js
> const privateKeyBase58 =
  '3Mmk4UzTRJTEtxaKk61LxtgUxAa2Dg36jF6VogPtRiKvfpsQWKPCLesKSV182RMmvM'
  + 'JKk6QErH3wgdHp8itkSSiF';
> const options = {
  publicKeyBase58: 'GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq',
  privateKeyBase58
};
> const EDKey = new Ed25519KeyPair(options);
> EDKey
Ed25519KeyPair { ...
```
<a name="Ed25519KeyPair+publicKey"></a>

### ed25519KeyPair.publicKey ⇒ <code>string</code>
Returns the Base58 encoded public key.

**Kind**: instance property of [<code>Ed25519KeyPair</code>](#Ed25519KeyPair)  
**Implements**: <code>LDKeyPair#publicKey</code>  
**Returns**: <code>string</code> - The Base58 encoded public key.  
**Read only**: true  
**See**: [publicKey](./LDKeyPair.md#publicKey)  
<a name="Ed25519KeyPair+privateKey"></a>

### ed25519KeyPair.privateKey ⇒ <code>string</code>
Returns the Base58 encoded private key.

**Kind**: instance property of [<code>Ed25519KeyPair</code>](#Ed25519KeyPair)  
**Implements**: <code>LDKeyPair#privateKey</code>  
**Returns**: <code>string</code> - The Base58 encoded private key.  
**Read only**: true  
**See**: [privateKey](./LDKeyPair.md#privateKey)  
<a name="Ed25519KeyPair+signer"></a>

### ed25519KeyPair.signer() ⇒ <code>Object</code>
Returns a signer object for use with
[jsonld-signatures](https://github.com/digitalbazaar/jsonld-signatures).

**Kind**: instance method of [<code>Ed25519KeyPair</code>](#Ed25519KeyPair)  
**Returns**: <code>Object</code> - A signer for the json-ld block.  
**Example**  
```js
> const signer = keyPair.signer();
> signer
{ sign: [AsyncFunction: sign] }
> signer.sign({data});
```
<a name="Ed25519KeyPair+verifier"></a>

### ed25519KeyPair.verifier() ⇒ <code>Object</code>
Returns a verifier object for use with
[jsonld-signatures](https://github.com/digitalbazaar/jsonld-signatures).

**Kind**: instance method of [<code>Ed25519KeyPair</code>](#Ed25519KeyPair)  
**Returns**: <code>Object</code> - Used to verify jsonld-signatures.  
**Example**  
```js
> const verifier = keyPair.verifier();
> verifier
{ verify: [AsyncFunction: verify] }
> verifier.verify(key);
```
<a name="Ed25519KeyPair+addEncodedPublicKey"></a>

### ed25519KeyPair.addEncodedPublicKey(publicKeyNode) ⇒ <code>Object</code>
Adds a public key base to a public key node.

**Kind**: instance method of [<code>Ed25519KeyPair</code>](#Ed25519KeyPair)  
**Returns**: <code>Object</code> - A PublicKeyNode in a block.  

| Param | Type | Description |
| --- | --- | --- |
| publicKeyNode | <code>Object</code> | The public key node in a jsonld-signature. |
| publicKeyNode.publicKeyBase58 | <code>string</code> | Base58 Public Key for [jsonld-signatures](https://github.com/digitalbazaar/jsonld-signatures). |

**Example**  
```js
> keyPair.addEncodedPublicKey({});
{ publicKeyBase58: 'GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq' }
```
<a name="Ed25519KeyPair+addEncryptedPrivateKey"></a>

### ed25519KeyPair.addEncryptedPrivateKey(keyNode) ⇒ <code>Object</code>
Adds an encrypted private key to the KeyPair.

**Kind**: instance method of [<code>Ed25519KeyPair</code>](#Ed25519KeyPair)  
**Returns**: <code>Object</code> - The keyNode with an encrypted private key attached.  

| Param | Type | Description |
| --- | --- | --- |
| keyNode | <code>Object</code> | A plain object. |

<a name="Ed25519KeyPair+encrypt"></a>

### ed25519KeyPair.encrypt(privateKey, password) ⇒ <code>Promise.&lt;JWE&gt;</code>
Produces a 32-byte encrypted key.

**Kind**: instance method of [<code>Ed25519KeyPair</code>](#Ed25519KeyPair)  
**Returns**: <code>Promise.&lt;JWE&gt;</code> - Produces JSON Web encrypted content.  
**See**: [JWE](./index.md#JWE)  

| Param | Type | Description |
| --- | --- | --- |
| privateKey | <code>string</code> | The base58 private key. |
| password | <code>string</code> | The password. |

**Example**  
```js
> const encryptedContent = await edKeyPair
  .encrypt(privateKey, 'Test1244!');
```
<a name="Ed25519KeyPair+decrypt"></a>

### ed25519KeyPair.decrypt(jwe, password) ⇒ <code>Object</code>
Decrypts jwe content to a privateKey.

**Kind**: instance method of [<code>Ed25519KeyPair</code>](#Ed25519KeyPair)  
**Returns**: <code>Object</code> - A Base58 private key.  
**See**: [JWE](./index.md#JWE)  

| Param | Type | Description |
| --- | --- | --- |
| jwe | <code>JWE</code> | Encrypted content from a block. |
| password | <code>string</code> | Password for the key used to sign the content. |

<a name="Ed25519KeyPair+fingerprint"></a>

### ed25519KeyPair.fingerprint() ⇒ <code>string</code>
Generates and returns a multiformats encoded
ed25519 public key fingerprint (for use with cryptonyms, for example).

**Kind**: instance method of [<code>Ed25519KeyPair</code>](#Ed25519KeyPair)  
**Returns**: <code>string</code> - A verifiable cryptographic signature.  
**See**: https://github.com/multiformats/multicodec  
**Example**  
```js
> edKeyPair.fingerprint();
z6dfdsfdsfds3432423
```
<a name="Ed25519KeyPair+verifyFingerprint"></a>

### ed25519KeyPair.verifyFingerprint(fingerprint) ⇒ <code>Object</code>
Tests whether the fingerprint was
generated from a given key pair.

**Kind**: instance method of [<code>Ed25519KeyPair</code>](#Ed25519KeyPair)  
**Returns**: <code>Object</code> - An object indicating valid is true or false.  

| Param | Type | Description |
| --- | --- | --- |
| fingerprint | <code>string</code> | A Base58 public key. |

**Example**  
```js
> edKeyPair.verifyFingerprint('z2S2Q6MkaFJewa');
{valid: true};
```
<a name="Ed25519KeyPair.generate"></a>

### Ed25519KeyPair.generate([options]) ⇒ [<code>Promise.&lt;Ed25519KeyPair&gt;</code>](#Ed25519KeyPair)
Generates a KeyPair with an optional deterministic seed.

**Kind**: static method of [<code>Ed25519KeyPair</code>](#Ed25519KeyPair)  
**Returns**: [<code>Promise.&lt;Ed25519KeyPair&gt;</code>](#Ed25519KeyPair) - Generates a key pair.  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [options] | <code>KeyPairOptions</code> | <code>{}</code> | See LDKeyPair docstring for full list. |
| [options.seed] | <code>Uint8Array</code> \| <code>Buffer</code> |  | a 32-byte array seed for a deterministic key. |

**Example**  
```js
> const keyPair = await Ed25519KeyPair.generate();
> keyPair
Ed25519KeyPair { ...
```
<a name="Ed25519KeyPair.from"></a>

### Ed25519KeyPair.from(options) ⇒ [<code>Ed25519KeyPair</code>](#Ed25519KeyPair)
Creates an Ed25519 Key Pair from an existing private key.

**Kind**: static method of [<code>Ed25519KeyPair</code>](#Ed25519KeyPair)  
**Returns**: [<code>Ed25519KeyPair</code>](#Ed25519KeyPair) - An Ed25519 Key Pair.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>Object</code> | Contains a private key. |
| [options.privateKey] | <code>Object</code> | A private key object. |
| [options.privateKeyBase58] | <code>string</code> | A Base58 Private key string. |

**Example**  
```js
> const options = {
  privateKeyBase58: privateKey
};
> const key = await Ed25519KeyPair.from(options);
> key
Ed25519KeyPair { ...
```

---
Copyright (c) 2018-2019 Digital Bazaar, Inc. All rights reserved.
