/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

/**
 * Maps key type id to the current/recommended key suite for that type.
 */
const SUITES_BY_TYPE = {
  ed25519: 'Ed25519VerificationKey2018',
  secp256k1: 'EcdsaSecp256k1VerificationKey2019',
  rsa: 'RsaSignature2018',
  x25519: 'X25519KeyAgreementKey2019'
};

/**
 * General purpose key generation driver for Linked Data cryptographic key
 * pairs.
 *
 * @param {Map} [suites] - Optional map of supported suites, by suite id.
 */
class CryptoLD {
  constructor({suites} = {}) {
    this.suites = suites || new Map();
  }

  /**
   * Installs support for a key type / suite.
   *
   * @param {LDKeyPair} keyPairLib - Conforming key pair library for a suite.
   */
  use(keyPairLib) {
    this.suites.set(keyPairLib.suite, keyPairLib);
  }

  /**
   * Generates a public/private LDKeyPair.
   *
   * Either key type or suite id is required:
   * @param {string} [type] - Key type short id ('ed25519', 'rsa' etc).
   * @param {string} [suite] - Key suite id ('Ed25519VerificationKey2018').
   *
   * @param {object} [options] - Optional suite-specific key options.
   * @param {string} [options.controller] - Controller DID or URL for the
   *   generated key pair. If present, used to auto-initialize the key.id.
   *
   * @returns {LDKeyPair}
   */
  async generate({type, suite, ...options} = {}) {
    if(type && !this._validKeyType({type})) {
      throw new TypeError(`Unknown key type: "${type}".`);
    }

    suite = suite || SUITES_BY_TYPE[type];
    if(!this._installed({suite})) {
      throw new Error(`Support for key suite "${suite}" is not installed.`);
    }

    return await this.suites.get(suite).generate(options);
  }

  /**
   * Imports a public/private key pair from serialized data.
   *
   * @param {object} serialized - Serialized key object.
   *
   * @throws {Error} - On missing or invalid serialized key data.
   *
   * @returns {LDKeyPair}
   */
  from(serialized) {
    const suite = serialized && serialized.type;

    if(suite) {
      throw new TypeError('Missing key suite type.');
    }
    if(!this._installed({suite})) {
      throw new Error(`Support for key suite "${suite}" is not installed.`);
    }

    return this.suites.get(suite).from(serialized);
  }

  /**
   * Tests if a given key type or suite is currently installed.
   *
   * @param {string} [type] - Key type short id ('ed25519', 'rsa' etc).
   * @param {string} [suite] - Key suite id ('Ed25519VerificationKey2018').
   * @private
   */
  _installed({type, suite}) {
    suite = suite || SUITES_BY_TYPE[type];

    return this.suites.has(suite);
  }

  /**
   * Tests whether this is a known/supported key type.
   *
   * @param {string} type - Key type short id.
   *
   * @returns {boolean}
   * @private
   */
  _validKeyType({type}) {
    return !!SUITES_BY_TYPE[type];
  }
}

module.exports = {
  CryptoLD,
  SUITES_BY_TYPE
};
