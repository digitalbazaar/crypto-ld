/*!
 * Copyright (c) 2018-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

/**
 * When adding support for a new suite type for `crypto-ld`, developers should
 * do the following:
 *
 * 1. Create their own npm package / github repo, such as `example-key-pair`.
 * 2. Subclass either LDVerifierKeyPair (for signature-related suites), or
 *    LDKeyPair (for all other types, such as key-agreement-related).
 * 3. Add to the key type table in the `crypto-ld` README.md (that's this repo).
 */
class LDKeyPair {
  /**
   * Creates a public/private key pair instance. This is an abstract base class,
   * actual key material and suite-specific methods are handled in the subclass.
   *
   * To generate or import a key pair, use the `cryptoLd` instance.
   * @see CryptoLD.js
   *
   * @param {string} id - The Key id, typically composed of controller
   *   URL and key fingerprint as hash fragment.
   * @param {string} controller - DID/URL of the person/entity
   *   controlling this key.
   */
  constructor({id, controller} = {}) {
    this.id = id;
    this.controller = controller;
    // this.type is set in subclass constructor
  }

  /**
   * Generates a new public/private key pair instance.
   * Note that this method is not typically called directly by client code,
   * but instead is used through a `cryptoLd` instance.
   *
   * @param {object} options - Suite-specific options for the KeyPair. For
   *   common options, see the `LDKeyPair.constructor()` docstring.
   *
   * @returns {Promise<LDKeyPair>} An LDKeyPair instance.
   */
  static async generate(/* options */) {
    throw new Error('Abstract method, must be implemented in subclass.');
  }

  /**
   * Generates a KeyPair from some options.
   * @param {object} options  - Will generate a key pair
   * in multiple different formats.
   * @example
   * > const options = {
   *    type: 'Ed25519VerificationKey2018'
   *   };
   * > const edKeyPair = await LDKeyPair.from(options);
   *
   * @returns {Promise<LDKeyPair>} A LDKeyPair.
   * @throws Unsupported Key Type.
   */
  static async from(/* options */) {
    throw new Error('Abstract method, must be implemented in subclass.');
  }

  /**
   * Exports the serialized representation of the KeyPair
   * and other information that json-ld Signatures can use to form a proof.
   *
   * @param {boolean} [publicKey] - Export public key material?
   * @param {boolean} [privateKey] - Export private key material?
   *
   * @returns {object} A public key object
   *   information used in verification methods by signatures.
   */
  export({publicKey = false, privateKey = false} = {}) {
    if(!publicKey && !privateKey) {
      throw new Error(
        'Export requires specifying either "publicKey" or "privateKey".');
    }
    const key = {
      id: this.id,
      type: this.type,
      controller: this.controller
    };
    if(publicKey) {
      this.addPublicKey({key}); // Subclass-specific
    }
    if(privateKey) {
      this.addPrivateKey({key}); // Subclass-specific
    }
    return key;
  }

  /**
   * Adds the suite-specific public key material, serialized to string, to
   * the exported public key node.
   * @param {object} key - Public key object.
   * @returns {object}
   */
  addPublicKey(/* {key} */) {
    throw new Error('Abstract method, must be implemented in subclass.');
  }

  /**
   * Adds the suite-specific private key material, serialized to string, to
   * the exported public key node.
   *
   * @param {object} key - Private key object.
   * @returns {object}
   */
  addPrivateKey(/* {key} */) {
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
   * belonging to this key pair.
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
  LDKeyPair
};
