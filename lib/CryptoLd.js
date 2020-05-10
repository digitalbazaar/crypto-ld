/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

/**
 * Maps key type id to the current/recommended key suite for that type.
 */
const SUITES_BY_TYPE = {
  'ed25519': 'Ed25519VerificationKey2018',
  'secp256k1': 'EcdsaSecp256k1VerificationKey2019',
  'rsa': 'RsaSignature2018',
  'x25519': 'X25519KeyAgreementKey2019'
}

/**
 * General purpose key generation driver for Linked Data cryptographic key
 * pairs.
 *
 * @param {Map} [drivers] - Optional map of supported drivers, by suite id.
 */
class CryptoLd {
  constructor({drivers} = {}) {
    this.drivers = drivers || new Map();
  }

  /**
   * Installs support for a key type / suite.
   *
   * @param {object} driver - Conforming key type driver library for a
   *   particular suite.
   */
  use(driver) {
    this.drivers.set(driver.suite, driver);
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

    return await this.drivers.get(suite).generate(options)
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

    return this.drivers.get(suite).from(serialized);
  }

  /**
   * Tests if a given key type or suite driver is currently installed.
   *
   * @param {string} [type] - Key type short id ('ed25519', 'rsa' etc).
   * @param {string} [suite] - Key suite id ('Ed25519VerificationKey2018').
   * @private
   */
  _installed({type, suite}) {
    suite = suite || SUITES_BY_TYPE[type];

    return this.drivers.has(suite);
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
  CryptoLd
};
