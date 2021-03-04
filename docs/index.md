## Usage

## Typedefs

<dl>
<dt><a href="#JWE">JWE</a> : <code>Object</code></dt>
<dd><p><a href="https://tools.ietf.org/html/rfc7516">JSON Web encryption</a></p>
</dd>
<dt><a href="#PSS">PSS</a> : <code>Object</code></dt>
<dd><p>PSS Object</p>
</dd>
<dt><a href="#KeyPairOptions">KeyPairOptions</a> : <code>Object</code></dt>
<dd><p>KeyPair Options.</p>
</dd>
<dt><a href="#SerializedLdKey">SerializedLdKey</a> : <code>Object</code></dt>
<dd><p>Serialized LD Key.</p>
</dd>
</dl>

<a name="JWE"></a>

## JWE : <code>Object</code>
[JSON Web encryption](https://tools.ietf.org/html/rfc7516)

**Kind**: global typedef  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| unprotected | <code>string</code> | A header for the jwe. |
| iv | <code>string</code> | A base64 url. |
| ciphertext | <code>string</code> | A base64 url. |
| tag | <code>string</code> | A base64 url. |

<a name="PSS"></a>

## PSS : <code>Object</code>
PSS Object

**Kind**: global typedef  
**Properties**

| Name | Type |
| --- | --- |
| encode | <code>function</code> | 
| verify | <code>function</code> | 

<a name="KeyPairOptions"></a>

## KeyPairOptions : <code>Object</code>
KeyPair Options.

**Kind**: global typedef  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| passphrase | <code>string</code> | For encrypting the private key. |
| id | <code>string</code> | Key Id. |
| controller | <code>string</code> | DID or URI of the person/entity controlling this key. |

<a name="SerializedLdKey"></a>

## SerializedLdKey : <code>Object</code>
Serialized LD Key.

**Kind**: global typedef  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| type | <code>Ed25519VerificationKey2018</code> \| <code>RsaVerificationKey2018</code> | The Encryption type. |
| passphrase | <code>string</code> | The passphrase to generate the pair. |


---
Copyright (c) 2018-2019 Digital Bazaar, Inc. All rights reserved.
