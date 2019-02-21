/*!
 * Copyright (c) 2018-2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const env = require('./env');
const forge = require('node-forge');
const base64url = require('base64url-universal');
const {pki: {ed25519}, util: {binary: {base58}}} = forge;
const LDKeyPair = require('./LDKeyPair');

class Ed25519KeyPair extends LDKeyPair {
  /**
   * @param options {object} See LDKeyPair constructor docstring for full list
   *
   * @param [options.publicKeyBase58] {string}
   * @param [options.privateKeyBase58] {string}
   */
  constructor(options = {}) {
    super(options);
    this.type = 'Ed25519VerificationKey2018';
    this.privateKeyBase58 = options.privateKeyBase58;
    this.publicKeyBase58 = options.publicKeyBase58;
  }

  get publicKey() {
    return this.publicKeyBase58;
  }

  get privateKey() {
    return this.privateKeyBase58;
  }

  /**
   * @param [options] {object} See LDKeyPair docstring for full list
   *
   * @returns {Promise<Ed25519KeyPair>}
   */
  static async generate(options = {}) {
    if(env.nodejs) {
      // TODO: use native node crypto api once it's available
      const sodium = require('sodium-native');
      const bs58 = require('bs58');
      const publicKey = new Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
      const privateKey = new Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
      sodium.crypto_sign_keypair(publicKey, privateKey);
      return new Ed25519KeyPair({
        publicKeyBase58: bs58.encode(publicKey),
        privateKeyBase58: bs58.encode(privateKey),
        ...options
      });
    }

    const {publicKey, privateKey} = ed25519.generateKeyPair();
    return new Ed25519KeyPair({
      publicKeyBase58: base58.encode(publicKey),
      privateKeyBase58: base58.encode(privateKey),
      ...options
    });
  }

  static async from(options) {
    const privateKeyBase58 = options.privateKeyBase58 ||
      // legacy privateDidDoc format
      (options.privateKey && options.privateKey.privateKeyBase58);
    const keyPair = new Ed25519KeyPair({
      privateKeyBase58,
      type: options.type || options.keyType, // Todo: deprecate keyType usage
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
    return ed25519SignerFactory(this);
  }

  /**
   * Returns a verifier object for use with jsonld-signatures.
   *
   * @returns {{verify: function}}
   */
  verifier() {
    return ed25519VerifierFactory(this);
  }

  addEncodedPublicKey(publicKeyNode) {
    publicKeyNode.publicKeyBase58 = this.publicKeyBase58;
    return publicKeyNode;
  }

  async addEncryptedPrivateKey(keyNode) {
    if(this.passphrase !== null) {
      keyNode.privateKeyJwe = await this.encrypt(
        {privateKeyBase58: this.privateKeyBase58},
        this.passphrase
      );
    } else {
      // no passphrase, do not encrypt private key
      keyNode.privateKeyBase58 = this.privateKeyBase58;
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
    const buffer = new forge.util.createBuffer();

    // ed25519 cryptonyms are multicodec encoded values, specifically:
    // (multicodec ed25519-pub 0xed01 + key bytes)
    const pubkeyBytes = _base58Decode({
      decode: base58.decode,
      keyMaterial: this.publicKeyBase58,
      type: 'public'
    });
    buffer.putBytes(forge.util.hexToBytes('ed01'));
    buffer.putBytes(pubkeyBytes.toString('binary'));

    // prefix with `z` to indicate multibase base58btc encoding
    return `z${base58.encode(buffer)}`;
  }

  /**
   * Tests whether the fingerprint was generated from a given key pair.
   *
   * @param fingerprint {string}
   *
   * @returns {boolean}
   */
  verifyFingerprint(fingerprint) {
    // fingerprint should have `z` prefix indicating that it's multibase encoded
    if(!(typeof fingerprint === 'string' && fingerprint[0] === 'z')) {
      return {
        error: new Error('`fingerprint` must be a multibase encoded string.'),
        valid: false
      };
    }
    let fingerprintBuffer;
    try {
      fingerprintBuffer = _base58Decode({
        decode: base58.decode,
        keyMaterial: fingerprint.slice(1),
        type: `fingerprint's`
      });
    } catch(e) {
      return {error: e, valid: false};
    }
    let publicKeyBuffer;
    try {
      publicKeyBuffer = _base58Decode({
        decode: base58.decode,
        keyMaterial: this.publicKeyBase58,
        type: 'public'
      });
    } catch(e) {
      return {error: e, valid: false};
    }

    // validate the first two multicodec bytes 0xed01
    const valid = fingerprintBuffer.slice(0, 2).toString('hex') === 'ed01' &&
      publicKeyBuffer.equals(fingerprintBuffer.slice(2));
    if(!valid) {
      return {
        error: new Error('The fingerprint does not match the public key.'),
        valid: false
      };
    }
    return {valid};
  }
}

/**
 * Returns a signer object for use with jsonld-signatures.
 *
 * @returns {{sign: function}}
 */
function ed25519SignerFactory(key) {
  if(!key.privateKeyBase58) {
    return {
      async sign() {
        throw new Error('No private key to sign with.');
      }
    };
  }

  if(env.nodejs) {
    const sodium = require('sodium-native');
    const bs58 = require('bs58');
    const privateKey = _base58Decode({
      decode: bs58.decode,
      keyMaterial: key.privateKeyBase58,
      type: 'private'
    });
    return {
      async sign({data}) {
        const signature = Buffer.alloc(sodium.crypto_sign_BYTES);
        await sodium.crypto_sign_detached(
          signature,
          Buffer.from(data.buffer, data.byteOffset, data.length),
          privateKey);
        return signature;
      }
    };
  }

  // browser implementation
  const privateKey = _base58Decode({
    decode: base58.decode,
    keyMaterial: key.privateKeyBase58,
    type: 'private'
  });
  return {
    async sign({data}) {
      return ed25519.sign({message: data, privateKey});
    }
  };
}

/**
 * Returns a verifier object for use with jsonld-signatures.
 *
 * @returns {{verify: function}}
 */
function ed25519VerifierFactory(key) {
  if(env.nodejs) {
    const sodium = require('sodium-native');
    const bs58 = require('bs58');
    const publicKey = _base58Decode({
      decode: bs58.decode,
      keyMaterial: key.publicKeyBase58,
      type: 'public'
    });
    return {
      async verify({data, signature}) {
        return sodium.crypto_sign_verify_detached(
          Buffer.from(signature.buffer, signature.byteOffset, signature.length),
          Buffer.from(data.buffer, data.byteOffset, data.length),
          publicKey);
      }
    };
  }

  // browser implementation
  const publicKey = _base58Decode({
    decode: base58.decode,
    keyMaterial: key.publicKeyBase58,
    type: 'public'
  });
  return {
    async verify({data, signature}) {
      return ed25519.verify({message: data, signature, publicKey});
    }
  };
}

/**
 * Wrap Base58 decoding operations in order to provide consistent error
 * messages.
 *
 * @param {function} decode - the decode function to use.
 * @param {string} keyMaterial - the Base58 encoded key material to decode.
 * @param {string} type - a description of the keyMaterial that will be included
 *   in an error message (e.g. 'public', 'private').
 *
 * @returns {bytes} - the decoded bytes. The data structure for the bytes is
 *   determined by the provided decode function.
 */
function _base58Decode({decode, keyMaterial, type}) {
  let bytes;
  try {
    bytes = decode(keyMaterial);
  } catch(e) {
    // do nothing
    // the bs58 implementation throws, forge returns undefined
    // this helper throws when no result is produced
  }
  if(bytes === undefined) {
    throw new TypeError(`The ${type} key material must be Base58 encoded.`);
  }
  return bytes;
}

module.exports = Ed25519KeyPair;
