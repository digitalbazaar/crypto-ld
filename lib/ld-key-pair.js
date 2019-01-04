/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const forge = require('node-forge');
const base64url = require('base64url');

const Injector = require('./Injector');

const DEFAULT_RSA_KEY_BITS = 2048;
const DEFAULT_RSA_EXPONENT = 0x10001;

class LDKeyPair {
  /**
   * @param options {object}
   * @param [options.injector] {Injector}
   *
   * @param [options.type] {string} Key type,
   *   for example 'Ed25519VerificationKey2018' or 'RsaVerificationKey2018'
   *
   * @param [options.publicKey] {string} base58-encoded or PEM-encoded
   * @param [options.privateKey] {string}
   * @param [options.passphrase=null] {string} For encrypting the private key
   *
   * @param [options.id] {string} Key id
   * @param [options.owner] {string} DID or URI of owner
   */
  constructor(options) {
    this.injector = options.injector || new Injector();
    this.type = options.type;
    this.publicKey = options.publicKey;
    this.privateKey = options.privateKey;
    this.passphrase = options.passphrase || null;
    this.id = options.id;
    this.owner = options.owner;
  }

  /**
   * @param [options]
   * @param [options.type] {string} Key type
   * @param [options.injector]
   * @param [options.passphrase]
   *
   * @returns {Promise<LDKeyPair>}
   */
  static async generate(options) {
    switch(options.type) {
      case 'Ed25519VerificationKey2018':
        return Ed25519KeyPair.generate(options);

      case 'RsaVerificationKey2018':
        return RSAKeyPair.generate(options);

      default:
        throw new Error(`Unsupported Key Type: ${options.type}`);
    }
  }

  /**
   * @param data {object} Serialized LD key object
   * @param [options.type] {string} Key type
   *
   * @param [options]
   * @param [options.injector]
   * @param [options.passphrase]
   *
   * @returns {Promise<LDKeyPair>}
   */
  static async from(data, options) {
    switch(data.type) {
      case 'Ed25519VerificationKey2018':
        return Ed25519KeyPair.from(data, options);

      case 'RsaVerificationKey2018':
        return RSAKeyPair.from(data, options);

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
   * @param controller {string} DID of key owner
   */
  publicNode({controller}) {
    const publicNode = {
      id: this.id,
      type: this.type,
      controller
    };
    this.addEncodedPublicKey(publicNode);
    return publicNode;
  }
}

class Ed25519KeyPair extends LDKeyPair {
  constructor(options) {
    super(options);
    // currently node only
    if(!this.injector.env.nodejs) {
      throw new Error(
        '"Ed25519VerificationKey2018" is not supported on this platform yet.');
    }
  }

  /**
   * @param [options]
   * @param [options.type]
   * @param [options.injector]
   *
   * @returns {Promise<Ed25519KeyPair>}
   */
  static async generate(options) {
    const bs58 = require('bs58');
    const chloride = require('chloride');
    const keyPair = chloride.crypto_sign_keypair();

    const keys = new Ed25519KeyPair({
      publicKey: bs58.encode(keyPair.publicKey),
      privateKey: bs58.encode(keyPair.secretKey),
      ...options
    });

    return keys;
  }

  static async from(data, options) {
    const privateKey = data.privateKeyBase58 ||
      (data.privateKey && data.privateKey.privateKeyBase58); // legacy privateDidDoc format
    const keyPair = new Ed25519KeyPair({
      publicKey: data.publicKeyBase58,
      privateKey: privateKey,
      id: data.id,
      type: data.type || data.keyType, // Todo: deprecate keyType usage
      owner: data.owner,
      ...options
    });

    return keyPair;
  }

  /**
   * Returns a signer object for use with jsonld-signatures.
   *
   * @returns {{sign: function}}
   */
  signer() {
    return {
      /**
       * @param data {?}
       * @returns {Promise<?>}
       */
      sign: async ({data}) => {
        const privateKey = forge.util.binary.base58.decode(this.privateKey);
        return forge.ed25519.sign({message: data, privateKey});
      }
    }
  }

  verifier() {
    return {
      /**
       * @param message {} buffer
       * @param signature {} rawSignature
       */
      verify: async ({message, signature}) => {
        const publicKey = forge.util.binary.base58.decode(this.publicKey);
        return forge.ed25519.verify({ message, signature, publicKey });
      }
    }
  }

  // publicKeyPem, publicKeyJwk, publicKeyHex, publicKeyBase64, publicKeyBase58
  async export() {
    const keyNode = {
      id: this.id,
      type: this.type,
      publicKeyBase58: this.publicKey
    };

    return this.addEncryptedPrivateKey(keyNode);
  }

  addEncodedPublicKey(publicKeyNode) {
    publicKeyNode.publicKeyBase58 = this.publicKey;
    return publicKeyNode;
  }

  async addEncryptedPrivateKey(keyNode) {
    if(this.passphrase !== null) {
      keyNode.privateKeyJwe = await this.encrypt(
        {privateKeyBase58: this.privateKey},
        this.passphrase
      );
    } else {
      // no passphrase, do not encrypt private key
      keyNode.privateKeyBase58 = this.privateKey;
    }
    return keyNode;
  }

  /**
   * @param privateKey
   * @param password
   *
   * @returns {Promise<JWE>}
   */
  async encrypt(privateKey, password) {
    const keySize = 32;
    const salt = forge.random.getBytesSync(32);
    const iterations = 4096;
    const key = await LDKeyPair.pbkdf2(password, salt, iterations, keySize);

    const jweHeader = {
      alg: 'PBES2-A128GCMKW',
      enc: 'A128GCMKW',
      jwk: {
        kty: 'PBKDF2',
        s: base64url.encode(salt),
        c: iterations
      }
    };

    // FIXME: this probably needs to be cleaned up/made more standard

    const iv = forge.random.getBytesSync(12);
    const cipher = forge.cipher.createCipher('AES-GCM', key);
    cipher.start({iv});
    cipher.update(forge.util.createBuffer(JSON.stringify(privateKey)));
    cipher.finish();
    const encrypted = cipher.output.getBytes();
    const tag = cipher.mode.tag.getBytes();

    const jwe = {
      unprotected: jweHeader,
      iv: base64url.encode(iv),
      ciphertext: base64url.encode(encrypted),
      tag: base64url.encode(tag)
    };

    return jwe;
  }

  async decrypt(jwe, password) {
    // FIXME: check header, implement according to JWE standard
    const keySize = 32;
    const {c: iterations} = jwe.unprotected.jwk;
    let {s: salt} = jwe.unprotected.jwk;
    salt = base64url.encode(salt);
    const key = await LDKeyPair.pbkdf2(password, salt, iterations, keySize);

    const iv = base64url.encode(jwe.iv);
    const tag = base64url.encode(jwe.tag);
    const decipher = forge.cipher.createDecipher('AES-GCM', key);
    decipher.start({iv, tag});
    decipher.update(base64url.encode(jwe.ciphertext));
    const pass = decipher.finish();
    if(!pass) {
      throw new Error('Invalid password.');
    }

    const privateKey = JSON.parse(decipher.output.getBytes());
    return privateKey;
  }

  /**
   * Generates and returns a Multiformat encoded ed25519 public key fingerprint
   * (for use with cryptonyms, for example).
   *
   * @see https://github.com/multiformats/multicodec
   *
   * @returns {string}
   */
  fingerprint() {
    const forge = this.injector.use('node-forge');
    const buffer = new forge.util.createBuffer();

    // ed25519 cryptonyms are multiformat encoded values, specifically:
    // (multicodec 0x30 + ed25519-pub 0xed + key bytes)
    const pubkeyBytes = forge.util.binary.base58.decode(this.publicKey);
    buffer.putBytes(forge.util.hexToBytes('30ed'));
    buffer.putBytes(pubkeyBytes.toString('binary'));

    return forge.util.binary.base58.encode(buffer);
  }

  /**
   * Tests whether the fingerprint was generated from a given key pair.
   *
   * @param fingerprint {string}
   *
   * @returns {boolean}
   */
  verifyFingerprint(fingerprint) {
    const forge = this.injector.use('node-forge');
    const fingerprintBuffer = forge.util.binary.base58.decode(fingerprint);
    const publicKeyBuffer = forge.util.binary.base58.decode(this.publicKey);

    // validate the first two multiformat bytes, 0x30 and 0xed
    return fingerprintBuffer.slice(0, 2).toString('hex') === '30ed' &&
      publicKeyBuffer.equals(fingerprintBuffer.slice(2));
  }
}

class RSAKeyPair extends LDKeyPair {
  /**
   * @param options
   * @param [options.keyBits]
   * @param [options.exponent]
   * @param [options.injector]
   *
   * @returns {Promise<RSAKeyPair>}
   */
  static async generate(options) {
    const keyBits = options.keyBits || DEFAULT_RSA_KEY_BITS;
    const exponent = options.exponent || DEFAULT_RSA_EXPONENT;

    if(options.injector.env.nodejs) {
      const ursa = require('ursa');
      const keyPair = ursa.generatePrivateKey(keyBits, exponent);
      return new RSAKeyPair({
        privateKey: forge.pki.privateKeyFromPem(keyPair.toPrivatePem()),
        publicKey: forge.pki.publicKeyFromPem(keyPair.toPublicPem()),
        ...options
      });
    }

    // Generate for browser
    return new Promise((resolve, reject) => {
      forge.pki.rsa.generateKeyPair(
        {bits: keyBits, e: exponent},
        (err, keyPair) => {
          if(err) {
            return reject(err);
          }
          resolve(new RSAKeyPair({
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey,
            ...options
          }));
        });
    });
  }

  static async from(data, options) {
    const privateKey = data.privateKeyPem ||
      (data.privateKey && data.privateKey.privateKeyPem); // legacy privateDidDoc format
    const keys = new RSAKeyPair({
      publicKey: forge.pki.publicKeyFromPem(data.publicKeyPem),
      privateKey: forge.pki.privateKeyFromPem(privateKey),
      id: data.id,
      type: data.type || data.keyType, // todo: deprecate keyType usage
      owner: data.owner,
      ...options
    });

    return keys;
  }

  async export() {
    const keyNode = {
      id: this.id,
      type: this.type
    };

    this.addEncodedPublicKey(keyNode);
    this.addEncryptedPrivateKey(keyNode);

    return keyNode;
  }

  addEncodedPublicKey(publicKeyNode) {
    publicKeyNode.publicKeyPem = forge.pki.publicKeyToPem(this.publicKey);
    return publicKeyNode;
  }

  async addEncryptedPrivateKey(keyNode) {
    if(this.passphrase !== null) {
      keyNode.privateKeyPem = forge.pki.encryptRsaPrivateKey(
        this.privateKey, this.passphrase, {algorithm: 'aes256'});
    } else {
      // no passphrase, do not encrypt private key
      keyNode.privateKeyPem = forge.pki.privateKeyToPem(this.privateKey);
    }
    return keyNode;
  }

  /**
   * Generates and returns a Multiformat encoded RSA public key fingerprint
   * (for use with cryptonyms, for example).
   *
   * @returns {string}
   */
  fingerprint() {
    const forge = this.injector.use('node-forge');
    const buffer = new forge.util.createBuffer();

    // use SubjectPublicKeyInfo fingerprint
    const fingerprintBuffer = forge.pki.getPublicKeyFingerprint(
      this.publicKey, {md: forge.md.sha256.create()});
    // RSA cryptonyms are multiformat encoded values, specifically they are:
    // (multicodec 0x30 + rsa-pub-fingerprint 0x5a + multihash 0x31 +
    //  sha2-256 0x12 + 32 byte value 0x20)
    buffer.putBytes(forge.util.hexToBytes('305a311220'));
    buffer.putBytes(fingerprintBuffer.bytes());

    return forge.util.binary.base58.encode(buffer);
  }
}

module.exports = {
  LDKeyPair,
  Ed25519KeyPair,
  RSAKeyPair
};
