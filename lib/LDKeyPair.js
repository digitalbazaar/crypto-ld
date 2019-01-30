/*!
 * Copyright (c) 2018-2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const forge = require('node-forge');

class LDKeyPair {
  /**
   * Note: Actual key material (like `publicKeyBase58` for Ed25519 or
   * `publicKeyPem` for RSA) is handled in the subclass.
   *
   * @param [options={}] {object}
   * @param [options.passphrase=null] {string} For encrypting the private key
   *
   * @param [options.id] {string} Key id
   *
   * @param [options.controller] {string} DID of the person/entity controlling
   *   this key
   * @param [options.owner] {string} DID or URI of owner. DEPRECATED, use
   *  `controller` instead.
   */
  constructor(options = {}) {
    this.passphrase = options.passphrase || null;
    this.id = options.id;
    this.controller = options.controller;
    this.owner = options.owner;
    // this.type is set in subclass constructor
    // this.publicKey* and this.privateKey* is handled in subclasses
  }

  /**
   * Returns subclass-appropriate public key material.
   */
  get publicKey() {
    throw new Error('Abstract method, must be implemented in subclass.');
  }

  /**
   * Returns subclass-appropriate private key material.
   */
  get privateKey() {
    throw new Error('Abstract method, must be implemented in subclass.');
  }

  /**
   * @param [options]
   * @param [options.type] {string} Key type
   * @param [options.passphrase]
   *
   * @returns {Promise<LDKeyPair>}
   */
  static async generate(options) {
    switch(options.type) {
      case 'Ed25519VerificationKey2018':
        const Ed25519KeyPair = require('./Ed25519KeyPair');
        return Ed25519KeyPair.generate(options);

      case 'RsaVerificationKey2018':
        const RSAKeyPair = require('./RSAKeyPair');
        return RSAKeyPair.generate(options);

      default:
        throw new Error(`Unsupported Key Type: ${options.type}`);
    }
  }

  /**
   * @param options {object} Serialized LD key object
   *
   * @param [options.type] {string} Key type
   *
   * @param [options]
   * @param [options.passphrase]
   *
   * @returns {Promise<LDKeyPair>}
   */
  static async from(options) {
    switch(options.type) {
      case 'Ed25519VerificationKey2018':
        const Ed25519KeyPair = require('./Ed25519KeyPair');
        return Ed25519KeyPair.from(options);

      case 'RsaVerificationKey2018':
        const RSAKeyPair = require('./RSAKeyPair');
        return RSAKeyPair.from(options);

      default:
        throw new Error(`Unsupported Key Type: ${options.type}`);
    }
  }

  static async pbkdf2(password, salt, iterations, keySize) {
    return new Promise((resolve, reject) => {
      forge.pkcs5.pbkdf2(password, salt, iterations, keySize, (err, key) =>
        err ? reject(err) : resolve(key));
    });
  }

  /**
   * @param [controller] {string} DID of the person/entity controlling this key
   *
   * @param [owner] {string} DID of key owner. Deprecated term, use `controller`
   */
  publicNode({controller = this.controller, owner = this.owner} = {}) {
    const publicNode = {
      id: this.id,
      type: this.type,
    };
    if(controller) {
      publicNode.controller = controller;
    }
    if(owner) {
      publicNode.owner = owner;
    }
    this.addEncodedPublicKey(publicNode); // Subclass-specific
    return publicNode;
  }

  // publicKeyPem, publicKeyJwk, publicKeyHex, publicKeyBase64, publicKeyBase58
  async export() {
    const keyNode = this.publicNode();
    return this.addEncryptedPrivateKey(keyNode); // Subclass-specific
  }
}

module.exports = LDKeyPair;
