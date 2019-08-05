/*!
 * Copyright (c) 2018-2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const forge = require('node-forge');
const {util: {binary: {base58}}} = forge;

class LDKeyPair {
  /**
   *  Note: Actual key material
   * (like `publicKeyBase58` for Ed25519 or
   * `publicKeyPem` for RSA) is handled in the subclass.
   * An LDKeyPair can encrypt private key material.
   * @classdesc The Abstract Base Class on which KeyPairs are based.
   * @example
   * // LDKeyPair is an Abstract Class and should only
   * // be used as a base class for other KeyPairs.
   * @param {KeyPairOptions} [options={}] -
   * See [KeyPairOptions]{@link ./index.md#KeyPairOptions}.
   * @param {string} [options.passphrase=null] - For encrypting the private key.
   * @param {string} options.id - The Key id.
   * @param {string} options.controller - DID of the person/entity controlling
   *   this key.
   * @param {string} [options.owner]  - DID or URI of owner. DEPRECATED, use
   *  `controller` instead.
   */
  constructor(options = {}) {
    this.passphrase = options.passphrase || null;
    this.id = options.id;
    this.controller = options.controller;
    this.owner = options.owner;
    // this.type is set in subclass constructor
    // this.publicKey* and this.privateKey* is handled in sub-classes
  }
  /**
   * @abstract
   * @interface
   * @readonly
   *  Returns the public key.
   * @throws  If not implemented by the subclass.
   *
   * @returns {string} A public key.
   */
  get publicKey() {
    throw new Error('Abstract method, must be implemented in subclass.');
  }
  /**
   * @abstract
   * @interface
   * @readonly
   *  Returns the private key.
   * @throws If not implemented by the subclass.
   *
   * @returns {string} A private key.
   */
  get privateKey() {
    throw new Error('Abstract method, must be implemented in subclass.');
  }
  /**
   * Generates an LdKeyPair using SerializedLdKey options.
   * @param {SerializedLdKey} options - Options for generating the KeyPair.
   * @example
   * > const options = {
   *    type: 'RsaVerificationKey2018',
   *    passphrase: 'Test1234'
   *  };
   * > const keyPair = await LDKeyPair.generate(options);
   *
   * @returns {Promise<LDKeyPair>} An LDKeyPair.
   * @throws Unsupported Key Type.
   * @see [SerializedLdKey]{@link ./index.md#SerializedLdKey}
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
   * Generates a KeyPair from some options.
   * @param {SerializedLdKey} options  - Will generate a key pair
   * in multiple different formats.
   * @see [SerializedLdKey]{@link ./index.md#SerializedLdKey}
   * @example
   * > const options = {
   *    type: 'Ed25519VerificationKey2018',
   *    passphrase: 'Test1234'
   *   };
   * > const edKeyPair = await LDKeyPair.from(options);
   *
   * @returns {Promise<LDKeyPair>} A LDKeyPair.
   * @throws Unsupported Key Type.
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

  /**
   * Creates an instance of LDKeyPair from a key fingerprint.
   * Note: Only key types that use their full public key in the fingerprint
   * are supported (so, currently, only 'ed25519').
   *
   * @param {string} fingerprint
   * @returns {LDKeyPair}
   * @throws Unsupported Fingerprint Type.
   */
  static fromFingerprint({fingerprint}) {
    // skip leading `z` that indicates base58 encoding
    const buffer = base58.decode(fingerprint.substr(1));

    // buffer is: 0xed 0x01 <public key bytes>
    if(buffer[0] === 0xed && buffer[1] === 0x01) {
      const Ed25519KeyPair = require('./Ed25519KeyPair');
      return new Ed25519KeyPair({
        publicKeyBase58: base58.encode(buffer.slice(2))
      });
    }

    throw new Error(`Unsupported Fingerprint Type: ${fingerprint}`);
  }

  /**
   * Generates a
   * [pdkdf2]{@link https://en.wikipedia.org/wiki/PBKDF2} key.
   * @param {string} password - The password for the key.
   * @param {string} salt - Noise used to randomize the key.
   * @param {number} iterations - The number of times to run the algorithm.
   * @param {number} keySize - The byte length of the key.
   * @example
   * > const key = await LdKeyPair.pbkdf2('Test1234', salt, 10, 32);
   *
   * @returns {Promise<Object>} A promise that resolves to a pdkdf2 key.
   * @see https://github.com/digitalbazaar/forge#pkcs5
   */
  static async pbkdf2(password, salt, iterations, keySize) {
    return new Promise((resolve, reject) => {
      forge.pkcs5.pbkdf2(password, salt, iterations, keySize, (err, key) =>
        err ? reject(err) : resolve(key));
    });
  }

  /**
   * Contains the encryption type & public key for the KeyPair
   * and other information that json-ld Signatures can use to form a proof.
   * @param {Object} [options={}] - Needs either a controller or owner.
   * @param {string} [options.controller=this.controller]  - DID of the
   * person/entity controlling this key pair.
   * @param {string} [options.owner=this.owner] - DID of key owner.
   * Deprecated term, use `controller`.
   * @example
   * > ldKeyPair.publicNode();
   * {id: 'test-keypair-id', owner: 'did:uuid:example'}
   *
   * @returns {Object} A public node with
   * information used in verification methods by signatures.
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
  /**
   * Exports the publicNode with an encrypted private key attached.
   * @example
   * > const withPrivateKey = await edKeyPair.export();
   *
   * @returns {KeyPairOptions} A public node with encrypted private key.
   * @see [KeyPairOptions]{@link ./index.md#KeyPairOptions}
   */
  async export() {
    const keyNode = this.publicNode();
    return this.addEncryptedPrivateKey(keyNode); // Subclass-specific
  }
}

module.exports = LDKeyPair;
