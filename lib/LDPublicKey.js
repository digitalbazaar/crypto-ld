/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

/**
 * When adding support for a new suite type for `crypto-ld`, developers should
 * do the following:
 *
 * 1. Create their own npm package / github repo, such as
 *    `example-verification-key-2020`.
 * 2. Subclass either LDVerifierPublicKey (for signature-related suites), or
 *    LDPublicKey (for all other types, such as key-agreement-related).
 * 3. Add to the key type table in the `crypto-ld` README.md (that's this repo).
 */
class LDPublicKey {
  /**
   * Creates a public key instance. This is an abstract base class,
   * actual key material and suite-specific methods are handled in the subclass.
   *
   * To generate or import a key, use the `cryptoLd` instance.
   * @see CryptoLD.js
   *
   * @param {string} id - The Key id, typically composed of controller
   *   URL and public key fingerprint as hash fragment.
   * @param {string} controller - DID/URL of the person/entity
   *   controlling this key.
   */
  constructor({id, controller} = {}) {
    this.id = id;
    this.controller = controller;
    // this.type is set in subclass constructor
  }

  /**
   * Generates a key instance from some options.
   *
   * @param {object} options - Key options (subclass-specific).
   *
   * @returns {Promise<LDPublicKey>} A new public key instance.
   */
  static async from(/* options */) {
    throw new Error('Abstract method, must be implemented in subclass.');
  }

  /**
   * Exports the serialized representation of the key
   * and other information that json-ld Signatures can use to verify a proof.
   *
   * @returns {object} A public key object
   *   information used in verification methods by signatures.
   */
  export() {
    const key = {
      id: this.id,
      type: this.type,
      controller: this.controller
    };
    this.exportPublicKeyMaterial({key}); // Subclass-specific
    return key;
  }

  /**
   * Adds the suite-specific public key material, serialized to string, to
   * the exported public key node.
   * @param {object} key - Public key object.
   * @returns {object}
   */
  exportPublicKeyMaterial(/* {key} */) {
    throw new Error('Abstract method, must be implemented in subclass.');
  }

  /**
   * Returns the public key fingerprint, multibase+multicodec encoded. The
   * specific fingerprint method is determined by the key suite, and is often
   * either a hash of the public key material (such as with RSA), or the
   * full encoded public key (for key types with sufficiently short
   * representations, such as ed25519).
   * This is frequently used in initializing the key id, or generating some
   * types of cryptonym DIDs.
   *
   * @returns {string}
   */
  fingerprint() {
    throw new Error('Abstract method, must be implemented in subclass.');
  }

  /**
   * Verifies that a given key fingerprint matches the public key material
   * belonging to this key.
   *
   * @param {string} fingerprint - Public key fingerprint.
   *
   * @returns {{verified: boolean}}
   */
  verifyFingerprint(/* {fingerprint} */) {
    throw new Error('Abstract method, must be implemented in subclass.');
  }
}

module.exports = {
  LDPublicKey
};
