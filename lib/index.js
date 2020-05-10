/*
 * Copyright (c) 2018-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

module.exports = {
  cryptoLd: require('./cryptoLd'),
  LDKeyPair: require('./LDKeyPair')
};

/**
 * PSS Object
 * @typedef {Object} PSS
 * @property encode {Function}
 * @property verify {Function}
 */

/**
 * KeyPair Options.
 * @typedef {Object} KeyPairOptions
 * @property {string} id - Key Id.
 * @property {string} controller -
 * DID of the person/entity controlling this key.
 */

/**
 * Serialized LD Key.
 * @typedef {Object} SerializedLdKey
 * @property {Ed25519VerificationKey2018|RsaVerificationKey2018}
 * type - The Encryption type.
 */
