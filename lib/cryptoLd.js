/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

/**
 * Maps key type id to the current/recommended key suite for that type.
 */
const SUITES = {
  'ed25519': 'Ed25519VerificationKey2018',
  'secp256k1': 'EcdsaSecp256k1VerificationKey2019',
  'rsa': 'RsaSignature2018',
  'x25519': 'X25519KeyAgreementKey2019'
}

/**
 * General purpose key generation driver for Linked Data cryptographic key
 * pairs.
 */
class CryptoLd {
  constructor({uses} = {}) {
    this.uses = uses || new Map();
  }

  /**
   * Installs support for a key type / suite.
   *
   * @param {object} driver - Conforming key type driver library for a
   *   particular suite.
   */
  use(driver) {
  }

  /**
   * Generates a public/private LDKeyPair.
   *
   * @param {string} [type]
   *
   * @returns {LDKeyPair}
   */
  generate({type} = {}) {
  }

  /**
   * Imports a public/private key pair from serialized data.
   *
   * @param {object} serialized
   *
   * @returns {LDKeyPair}
   */
  from(serialized) {
  }
}

module.exports = {
  CryptoLd
};
