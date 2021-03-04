## Usage

<a name="LDKeyPair"></a>

## LDKeyPair
The Abstract Base Class on which KeyPairs are based.

**Kind**: global class  

* [LDKeyPair](#LDKeyPair)
    * [new LDKeyPair([options])](#new_LDKeyPair_new)
    * _instance_
        * *[.publicKey](#LDKeyPair+publicKey) ⇒ <code>string</code>*
        * *[.privateKey](#LDKeyPair+privateKey) ⇒ <code>string</code>*
        * [.publicNode([options])](#LDKeyPair+publicNode) ⇒ <code>Object</code>
        * [.export()](#LDKeyPair+export) ⇒ <code>KeyPairOptions</code>
    * _static_
        * [.generate(options)](#LDKeyPair.generate) ⇒ [<code>Promise.&lt;LDKeyPair&gt;</code>](#LDKeyPair)
        * [.from(options)](#LDKeyPair.from) ⇒ [<code>Promise.&lt;LDKeyPair&gt;</code>](#LDKeyPair)
        * [.pbkdf2(password, salt, iterations, keySize)](#LDKeyPair.pbkdf2) ⇒ <code>Promise.&lt;Object&gt;</code>

<a name="new_LDKeyPair_new"></a>

### new LDKeyPair([options])
Note: Actual key material
(like `publicKeyBase58` for Ed25519 or
`publicKeyPem` for RSA) is handled in the subclass.
An LDKeyPair can encrypt private key material.


| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [options] | <code>KeyPairOptions</code> | <code>{}</code> | See [KeyPairOptions](./index.md#KeyPairOptions). |
| [options.passphrase] | <code>string</code> | <code>null</code> | For encrypting the private key. |
| options.id | <code>string</code> |  | The Key id. |
| options.controller | <code>string</code> |  | DID or URI of the person/entity controlling this key. |

**Example**  
```js
// LDKeyPair is an Abstract Class and should only
// be used as a base class for other KeyPairs.
```
<a name="LDKeyPair+publicKey"></a>

### *ldKeyPair.publicKey ⇒ <code>string</code>*
**Kind**: instance abstract interface of [<code>LDKeyPair</code>](#LDKeyPair)  
**Returns**: <code>string</code> - A public key.  
**Throws**:

- If not implemented by the subclass.

**Read only**: true  
<a name="LDKeyPair+privateKey"></a>

### *ldKeyPair.privateKey ⇒ <code>string</code>*
**Kind**: instance abstract interface of [<code>LDKeyPair</code>](#LDKeyPair)  
**Returns**: <code>string</code> - A private key.  
**Throws**:

- If not implemented by the subclass.

**Read only**: true  
<a name="LDKeyPair+publicNode"></a>

### ldKeyPair.publicNode([options]) ⇒ <code>Object</code>
Contains the encryption type & public key for the KeyPair
and other information that json-ld Signatures can use to form a proof.

**Kind**: instance method of [<code>LDKeyPair</code>](#LDKeyPair)  
**Returns**: <code>Object</code> - A public node with
information used in verification methods by signatures.  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [options] | <code>Object</code> | <code>{}</code> | |
| [options.controller] | <code>string</code> | <code>&quot;this.controller&quot;</code> | DID or URI of the person/entity controlling this key pair. |

**Example**  
```js
> ldKeyPair.publicNode();
{id: 'test-keypair-id', controller: 'did:uuid:example'}
```
<a name="LDKeyPair+export"></a>

### ldKeyPair.export() ⇒ <code>KeyPairOptions</code>
Exports the publicNode with an encrypted private key attached.

**Kind**: instance method of [<code>LDKeyPair</code>](#LDKeyPair)  
**Returns**: <code>KeyPairOptions</code> - A public node with encrypted private key.  
**See**: [KeyPairOptions](./index.md#KeyPairOptions)  
**Example**  
```js
> const withPrivateKey = await edKeyPair.export();
```
<a name="LDKeyPair.generate"></a>

### LDKeyPair.generate(options) ⇒ [<code>Promise.&lt;LDKeyPair&gt;</code>](#LDKeyPair)
Generates an LdKeyPair using SerializedLdKey options.

**Kind**: static method of [<code>LDKeyPair</code>](#LDKeyPair)  
**Returns**: [<code>Promise.&lt;LDKeyPair&gt;</code>](#LDKeyPair) - An LDKeyPair.  
**Throws**:

- Unsupported Key Type.

**See**: [SerializedLdKey](./index.md#SerializedLdKey)  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>SerializedLdKey</code> | Options for generating the KeyPair. |

**Example**  
```js
> const options = {
   type: 'RsaVerificationKey2018',
   passphrase: 'Test1234'
 };
> const keyPair = await LDKeyPair.generate(options);
```
<a name="LDKeyPair.from"></a>

### LDKeyPair.from(options) ⇒ [<code>Promise.&lt;LDKeyPair&gt;</code>](#LDKeyPair)
Generates a KeyPair from some options.

**Kind**: static method of [<code>LDKeyPair</code>](#LDKeyPair)  
**Returns**: [<code>Promise.&lt;LDKeyPair&gt;</code>](#LDKeyPair) - A LDKeyPair.  
**Throws**:

- Unsupported Key Type.

**See**: [SerializedLdKey](./index.md#SerializedLdKey)  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>SerializedLdKey</code> | Will generate a key pair in multiple different formats. |

**Example**  
```js
> const options = {
   type: 'Ed25519VerificationKey2018',
   passphrase: 'Test1234'
  };
> const edKeyPair = await LDKeyPair.from(options);
```
<a name="LDKeyPair.pbkdf2"></a>

### LDKeyPair.pbkdf2(password, salt, iterations, keySize) ⇒ <code>Promise.&lt;Object&gt;</code>
Generates a
[pdkdf2](https://en.wikipedia.org/wiki/PBKDF2) key.

**Kind**: static method of [<code>LDKeyPair</code>](#LDKeyPair)  
**Returns**: <code>Promise.&lt;Object&gt;</code> - A promise that resolves to a pdkdf2 key.  
**See**: https://github.com/digitalbazaar/forge#pkcs5  

| Param | Type | Description |
| --- | --- | --- |
| password | <code>string</code> | The password for the key. |
| salt | <code>string</code> | Noise used to randomize the key. |
| iterations | <code>number</code> | The number of times to run the algorithm. |
| keySize | <code>number</code> | The byte length of the key. |

**Example**  
```js
> const key = await LdKeyPair.pbkdf2('Test1234', salt, 10, 32);
```

---
Copyright (c) 2018-2019 Digital Bazaar, Inc. All rights reserved.
