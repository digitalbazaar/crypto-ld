/*
 * Copyright (c) 2018-2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

module.exports = {
  Ed25519KeyPair: require('./Ed25519KeyPair'),
  LDKeyPair: require('./LDKeyPair'),
  RSAKeyPair: require('./RSAKeyPair'),
};

/**
 * [JSON Web encryption]{@link https://tools.ietf.org/html/rfc7516}
 * @typedef {Object} JWE
 * @property {string} unprotected - A header for the jwe.
 * @property {string} iv - A base64 url.
 * @property {string} ciphertext - A base64 url.
 * @property {string} tag - A base64 url.
 */

/**
 * PSS Object
 * @typedef {Object} PSS
 * @property encode {Function}
 * @property verify {Function}
 */

/**
 * KeyPair Options.
 * @typedef {Object} KeyPairOptions
 * @property {string} passphrase - For encrypting the private key.
 * @property {string} id - Key Id.
 * @property {string} controller -
 * DID of the person/entity controlling this key.
 * @property {string} owner - DID or URI of owner. DEPRECATED, use
 *  `controller` instead.
 */

/**
 * Serialized LD Key.
 * @typedef {Object} SerializedLdKey
 * @property {Ed25519VerificationKey2018|RsaVerificationKey2018}
 * type - The Encryption type.
 * @property {string} passphrase - The passphrase to generate the pair.
 */
