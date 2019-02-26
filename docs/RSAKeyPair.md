## Usage

## Classes

<dl>
<dt><a href="#RSAKeyPair">RSAKeyPair</a></dt>
<dd></dd>
</dl>

## Constants

<dl>
<dt><a href="#DEFAULT_RSA_KEY_BITS">DEFAULT_RSA_KEY_BITS</a> : <code>number</code></dt>
<dd></dd>
<dt><a href="#DEFAULT_RSA_EXPONENT">DEFAULT_RSA_EXPONENT</a> : <code>number</code></dt>
<dd></dd>
</dl>

<a name="RSAKeyPair"></a>

## RSAKeyPair
**Kind**: global class  

* [RSAKeyPair](#RSAKeyPair)
    * [new RSAKeyPair(options)](#new_RSAKeyPair_new)
    * _instance_
        * [.publicKey](#RSAKeyPair+publicKey) ⇒ <code>string</code>
        * [.privateKey](#RSAKeyPair+privateKey) ⇒ <code>string</code>
        * [.validateKeyParams()](#RSAKeyPair+validateKeyParams) ⇒ <code>undefined</code>
        * [.addEncodedPublicKey(publicKeyNode)](#RSAKeyPair+addEncodedPublicKey) ⇒ <code>KeyPairOptions</code>
        * [.addEncryptedPrivateKey(keyNode)](#RSAKeyPair+addEncryptedPrivateKey) ⇒ <code>KeyPairOptions</code>
        * [.fingerprint()](#RSAKeyPair+fingerprint) ⇒ <code>string</code>
        * [.signer()](#RSAKeyPair+signer) ⇒ <code>Object</code>
        * [.verifier()](#RSAKeyPair+verifier) ⇒ <code>Object</code>
    * _static_
        * [.generate([options])](#RSAKeyPair.generate) ⇒ [<code>Promise.&lt;RSAKeyPair&gt;</code>](#RSAKeyPair)
        * [.from(options)](#RSAKeyPair.from) ⇒ [<code>RSAKeyPair</code>](#RSAKeyPair)

<a name="new_RSAKeyPair_new"></a>

### new RSAKeyPair(options)
An implementation of
[RSA encryption](https://simple.wikipedia.org/wiki/RSA_algorithm)
for
[jsonld-signatures](https://github.com/digitalbazaar/jsonld-signatures).


| Param | Type | Description |
| --- | --- | --- |
| options | <code>KeyPairOptions</code> | Keys must be in RSA format other options must follow [KeyPairOptions](./index.md#KeyPairOptions). |
| options.publicKeyPem | <code>string</code> | Public Key for Signatures. |
| options.privateKeyPem | <code>string</code> | Your Confidential key for signing. |

**Example**  
```js
> const options = {
   privateKeyPem: 'testPrivateKey',
   publicKeyPem: 'testPublicKey'
 };
> const RSAKey = new RSAKeyPair(options);
```
<a name="RSAKeyPair+publicKey"></a>

### rsaKeyPair.publicKey ⇒ <code>string</code>
Returns the public key.

**Kind**: instance property of [<code>RSAKeyPair</code>](#RSAKeyPair)  
**Implements**: <code>LDKeyPair#publicKey</code>  
**Returns**: <code>string</code> - The public key.  
**Read only**: true  
**See**: [publicKey](./LDKeyPair.md#publicKey)  
<a name="RSAKeyPair+privateKey"></a>

### rsaKeyPair.privateKey ⇒ <code>string</code>
Returns the private key.

**Kind**: instance property of [<code>RSAKeyPair</code>](#RSAKeyPair)  
**Implements**: <code>LDKeyPair#privateKey</code>  
**Returns**: <code>string</code> - The private key.  
**Read only**: true  
**See**: [privateKey](./LDKeyPair.md#privateKey)  
<a name="RSAKeyPair+validateKeyParams"></a>

### rsaKeyPair.validateKeyParams() ⇒ <code>undefined</code>
Validates this key.

**Kind**: instance method of [<code>RSAKeyPair</code>](#RSAKeyPair)  
**Returns**: <code>undefined</code> - If it does not throw then the key is valid.  
**Throws**:

- Invalid RSA keyBit length
- Invalid RSA exponent

**Example**  
```js
> rsaKeyPair.validateKeyParams();
undefined
```
<a name="RSAKeyPair+addEncodedPublicKey"></a>

### rsaKeyPair.addEncodedPublicKey(publicKeyNode) ⇒ <code>KeyPairOptions</code>
Adds this KeyPair's publicKeyPem to a public node.

**Kind**: instance method of [<code>RSAKeyPair</code>](#RSAKeyPair)  
**Returns**: <code>KeyPairOptions</code> - A public node with a publicKeyPem set.  
**See**: [KeyPairOptions](./index.md#KeyPairOptions)  

| Param | Type | Description |
| --- | --- | --- |
| publicKeyNode | <code>KeyPairOptions</code> | A Node with out a publicKeyPem set. |

**Example**  
```js
> rsaKeyPair.addEncodedPublicKey({id: 'testnode'});
{ publicKeyPem: 'testPublicKey' }
```
<a name="RSAKeyPair+addEncryptedPrivateKey"></a>

### rsaKeyPair.addEncryptedPrivateKey(keyNode) ⇒ <code>KeyPairOptions</code>
Adds this KeyPair's privateKeyPem to a public node.

**Kind**: instance method of [<code>RSAKeyPair</code>](#RSAKeyPair)  
**Returns**: <code>KeyPairOptions</code> - A public node with a privateKeyPem set.  
**See**: [KeyPairOptions](./index.md#KeyPairOptions)  

| Param | Type | Description |
| --- | --- | --- |
| keyNode | <code>KeyPairOptions</code> | A Node with out a publicKeyPem set. |

**Example**  
```js
> rsaKeyPair.addEncryptedPrivateKey({id: 'testnode'});
{ privateKeyPem: 'testPrivateKey' }
```
<a name="RSAKeyPair+fingerprint"></a>

### rsaKeyPair.fingerprint() ⇒ <code>string</code>
Generates and returns a multiformats
encoded RSA public key fingerprint (for use with cryptonyms, for example).

**Kind**: instance method of [<code>RSAKeyPair</code>](#RSAKeyPair)  
**Returns**: <code>string</code> - An RSA fingerprint.  
**Example**  
```js
> rsaKeyPair.fingerprint();
3423dfdsf3432sdfdsds
```
<a name="RSAKeyPair+signer"></a>

### rsaKeyPair.signer() ⇒ <code>Object</code>
Returns a signer object with an async sign function for use by
[jsonld-signatures](https://github.com/digitalbazaar/jsonld-signatures)
to sign content in a signature.

**Kind**: instance method of [<code>RSAKeyPair</code>](#RSAKeyPair)  
**Returns**: <code>Object</code> - An RSA Signer Function for a single key.
for a single Private Key.  
**Example**  
```js
> const signer = rsaKeyPair.signer();
> signer.sign({data});
```
<a name="RSAKeyPair+verifier"></a>

### rsaKeyPair.verifier() ⇒ <code>Object</code>
Returns a verifier object with an async
function verify for use with
[jsonld-signatures](https://github.com/digitalbazaar/jsonld-signatures).

**Kind**: instance method of [<code>RSAKeyPair</code>](#RSAKeyPair)  
**Returns**: <code>Object</code> - An RSA Verifier Function for a single key.  
**Example**  
```js
> const verifier = rsaKeyPair.verifier();
> const valid = await verifier.verify({data, signature});
```
<a name="RSAKeyPair.generate"></a>

### RSAKeyPair.generate([options]) ⇒ [<code>Promise.&lt;RSAKeyPair&gt;</code>](#RSAKeyPair)
Generates an RSA KeyPair using the RSA Defaults.

**Kind**: static method of [<code>RSAKeyPair</code>](#RSAKeyPair)  
**Returns**: [<code>Promise.&lt;RSAKeyPair&gt;</code>](#RSAKeyPair) - A Default encrypted RSA KeyPair.  
**See**: [KeyPairOptions](./index.md#KeyPairOptions)  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [options] | <code>KeyPairOptions</code> | <code>{}</code> | See LDKeyPair docstring for full list. |

**Example**  
```js
> const keyPair = await RSAKeyPair.generate();
> keyPair
RSAKeyPair { ...
```
<a name="RSAKeyPair.from"></a>

### RSAKeyPair.from(options) ⇒ [<code>RSAKeyPair</code>](#RSAKeyPair)
Creates a RSA Key Pair from an existing private key.

**Kind**: static method of [<code>RSAKeyPair</code>](#RSAKeyPair)  
**Returns**: [<code>RSAKeyPair</code>](#RSAKeyPair) - An RSA Key Pair.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>Object</code> | Contains a private key. |
| [options.privateKey] | <code>Object</code> | A private key. |
| [options.privateKeyPem] | <code>string</code> | An RSA Private key. |

**Example**  
```js
> const options = {
   privateKeyPem: 'testkeypem'
 };
> const key = await RSAKeyPair.from(options);
```
<a name="DEFAULT_RSA_KEY_BITS"></a>

## DEFAULT\_RSA\_KEY\_BITS : <code>number</code>
**Kind**: global constant  
**Default**: <code>2048</code>  
<a name="DEFAULT_RSA_EXPONENT"></a>

## DEFAULT\_RSA\_EXPONENT : <code>number</code>
**Kind**: global constant  
**Default**: <code>65537</code>  

---
Copyright (c) 2018-2019 Digital Bazaar, Inc. All rights reserved.
