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

  async fromKeyId({
    keyId, documentLoader, checkContext = true, checkRevoked = true
  } = {}) {
    if(!keyId) {
      throw new TypeError('Key ID is required.');
    }
    if(!documentLoader) {
      throw new TypeError('Document loader is required.');
    }
    let keyDocument;
    try {
      ({doc: keyDocument} = await documentLoader(keyId));
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
      throw new Error(`Support for key type "${keySuite}" is not installed.`);
    }
    if(checkContext) {
      const fetchedDocContexts = [].concat(keyDocument['@context']);
      if(!fetchedDocContexts.includes(keySuite.SUITE_CONTEXT)) {
        throw new Error('Fetched document does not contain required context "' +
          keySuite.SUITE_CONTEXT + '".');
      }
    }
    if(checkRevoked && keyDocument.revoked) {
      // TODO: Check RFC3339 revocation. Perhaps a callback instead?
    }
    return keySuite.from(keyDocument);
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
