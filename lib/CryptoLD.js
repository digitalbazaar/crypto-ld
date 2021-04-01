/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

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
   * Installs support for a key type (suite).
   *
   * @param {LDKeyPair} keyPairLib - Conforming key pair library for a suite.
   */
  use(keyPairLib) {
    this.suites.set(keyPairLib.suite, keyPairLib);
  }

  /**
   * Generates a public/private LDKeyPair.
   *
   * @param {string} type - Key suite id ('Ed25519VerificationKey2020').
   *
   * @param {object} [options] - Optional suite-specific key options.
   * @param {string} [options.controller] - Controller DID or URL for the
   *   generated key pair. If present, used to auto-initialize the key.id.
   *
   * @returns {Promise<LDKeyPair>}
   */
  async generate({type, ...options} = {}) {
    if(!type) {
      throw new TypeError('A key type is required to generate.');
    }
    if(!this._installed({type})) {
      throw new TypeError(`Support for key type "${type}" is not installed.`);
    }

    return this.suites.get(type).generate(options);
  }

  /**
   * Imports a public/private key pair from serialized data.
   *
   * @param {object} serialized - Serialized key object.
   *
   * @throws {Error} - On missing or invalid serialized key data.
   *
   * @returns {Promise<LDKeyPair>}
   */
  async from(serialized = {}) {
    const type = serialized && serialized.type;

    if(!type) {
      throw new TypeError('Missing key type.');
    }
    if(!this._installed({type})) {
      throw new Error(`Support for key type "${type}" is not installed.`);
    }

    return this.suites.get(type).from(serialized);
  }

  /**
   * Imports a key pair instance via the provided `documentLoader` function,
   * optionally checking it for revocation and required context.
   *
   * @param {object} options - Options hashmap.
   * @param {string} options.id - Key ID or URI.
   * @param {Function} options.documentLoader - JSON-LD Document Loader.
   * @param {boolean} [options.checkContext=true] - Whether to check that the
   *   fetched key document contains the context required by the key's crypto
   *   suite.
   * @param {boolean} [options.checkRevoked=true] - Whether to check the key
   *   object for the presence of the `revoked` timestamp.
   *
   * @returns {Promise<LDKeyPair>} Resolves with the appropriate key pair
   *   instance.
   */
  async fromKeyId({
    id, documentLoader, checkContext = true, checkRevoked = true
  } = {}) {
    if(!id) {
      throw new TypeError('The "id" parameter is required.');
    }
    if(!documentLoader) {
      throw new TypeError('The "documentLoader" parameter is required.');
    }
    let keyDocument;
    try {
      ({document: keyDocument} = await documentLoader(id));
      // the supplied documentLoader may not be properly implemented
      if(!keyDocument) {
        throw new Error(
          'The "documentLoader" function must return a "document" object.');
      }
    } catch(e) {
      const error = new Error('Error fetching document: ' + e.message);
      error.cause = e;
      throw error;
    }
    const fetchedType = keyDocument.type;
    if(!fetchedType) {
      throw new Error('Key suite type not found in fetched document.');
    }
    const keySuite = this.suites.get(fetchedType);
    if(!keySuite) {
      throw new Error(`Support for suite "${fetchedType}" is not installed.`);
    }

    return keySuite.fromKeyDocument({document: keyDocument, checkContext,
      checkRevoked});
  }

  /**
   * Tests if a given key type is currently installed.
   *
   * @param {string} [type] - Key suite id ('Ed25519VerificationKey2020').
   * @private
   */
  _installed({type}) {
    return this.suites.has(type);
  }
}

module.exports = {
  CryptoLD
};
