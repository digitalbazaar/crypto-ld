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
   * An implementation of
   * [Ed25519 Signature 2018]{@link https://w3c-dvcg.github.io/lds-ed25519-2018/}
   * for
   * [jsonld-signatures.]{@link https://github.com/digitalbazaar/jsonld-signatures}
   * @example
   * > const privateKey =
   *   '3Mmk4UzTRJTEtxaKk61LxtgUxAa2Dg36jF6VogPtRiKvfpsQWKPCLesKSV182RMmvM'
   *   + 'JKk6QErH3wgdHp8itkSSiF';
   * > const options = {
   *   publicKeyBase58: 'GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq',
   *   privateKeyBase58: privateKey
   * };
   * > const EDKey = new Ed25519KeyPair(options);
   * > EDKey
   * Ed25519KeyPair { ...
   * @param {KeyPairOptions} options - Base58 keys plus
   * other options most follow
   * [KeyPairOptions]{@link ./index.md#KeyPairOptions}.
   * @param {string} options.publicKeyBase58 - Base58 encoded Public Key
   * unencoded is 32-bytes.
   * @param {string} options.privateKeyBase58 - Base58 Private Key
   * unencoded is 64-bytes.
   */
  constructor(options = {}) {
    super(options);
    this.type = 'Ed25519VerificationKey2018';
    this.privateKeyBase58 = options.privateKeyBase58;
    this.publicKeyBase58 = options.publicKeyBase58;
  }
  /**
   * Returns the Base58 encoded public key.
   * @implements {LDKeyPair#publicKey}
   * @readonly
   *
   * @returns {string} The Base58 encoded public key.
   * @see [publicKey]{@link ./LDKeyPair.md#publicKey}
   */
  get publicKey() {
    return this.publicKeyBase58;
  }
  /**
   * Returns the Base58 encoded private key.
   * @implements {LDKeyPair#privateKey}
   * @readonly
   *
   * @returns {string} The Base58 encoded private key.
   * @see [privateKey]{@link ./LDKeyPair.md#privateKey}
   */
  get privateKey() {
    return this.privateKeyBase58;
  }

  /**
   * Generates a KeyPair with an optional deterministic seed.
   * @example
   * > const keyPair = await Ed25519KeyPair.generate();
   * > keyPair
   * Ed25519KeyPair { ...
   * @param {KeyPairOptions} [options={}] - See LDKeyPair
   * docstring for full list.
   * @param {Uint8Array|Buffer} [options.seed] -
   * a 32-byte array seed for a deterministic key.
   *
   * @returns {Promise<Ed25519KeyPair>} Generates a key pair.
   */
  static async generate(options = {}) {
    if(env.nodejs) {
      // TODO: use native node crypto api once it's available
      const sodium = require('sodium-native');
      const bs58 = require('bs58');
      const publicKey = new Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
      const privateKey = new Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
      if('seed' in options) {
        sodium.crypto_sign_seed_keypair(publicKey, privateKey, options.seed);
      } else {
        sodium.crypto_sign_keypair(publicKey, privateKey);
      }
      return new Ed25519KeyPair({
        publicKeyBase58: bs58.encode(publicKey),
        privateKeyBase58: bs58.encode(privateKey),
        ...options
      });
    }

    const generateOptions = {};
    if('seed' in options) {
      generateOptions.seed = options.seed;
    }
    const {publicKey, privateKey} = ed25519.generateKeyPair(generateOptions);
    return new Ed25519KeyPair({
      publicKeyBase58: base58.encode(publicKey),
      privateKeyBase58: base58.encode(privateKey),
      ...options
    });
  }
  /**
   * Creates an Ed25519 Key Pair from an existing private key.
   * @example
   * > const options = {
   *   privateKeyBase58: privateKey
   * };
   * > const key = await Ed25519KeyPair.from(options);
   * > key
   * Ed25519KeyPair { ...
   * @param {Object} options - Contains a private key.
   * @param {Object} [options.privateKey] - A private key object.
   * @param {string} [options.privateKeyBase58] - A Base58
   * Private key string.
   *
   * @returns {Ed25519KeyPair} An Ed25519 Key Pair.
   */
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
   * Returns a signer object for use with
   * [jsonld-signatures]{@link https://github.com/digitalbazaar/jsonld-signatures}.
   * @example
   * > const signer = keyPair.signer();
   * > signer
   * { sign: [AsyncFunction: sign] }
   * > signer.sign({data});
   *
   * @returns {{sign: Function}} A signer for the json-ld block.
   */
  signer() {
    return ed25519SignerFactory(this);
  }

  /**
   * Returns a verifier object for use with
   * [jsonld-signatures]{@link https://github.com/digitalbazaar/jsonld-signatures}.
   * @example
   * > const verifier = keyPair.verifier();
   * > verifier
   * { verify: [AsyncFunction: verify] }
   * > verifier.verify(key);
   *
   * @returns {{verify: Function}} Used to verify jsonld-signatures.
   */
  verifier() {
    return ed25519VerifierFactory(this);
  }
  /**
   * Adds a public key base to a public key node.
   * @example
   * > keyPair.addEncodedPublicKey({});
   * { publicKeyBase58: 'GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq' }
   * @param {Object} publicKeyNode - The public key node in a jsonld-signature.
   * @param {string} publicKeyNode.publicKeyBase58 - Base58 Public Key for
   * [jsonld-signatures]{@link https://github.com/digitalbazaar/jsonld-signatures}.
   *
   * @returns {{verify: Function}} A PublicKeyNode in a block.
   */
  addEncodedPublicKey(publicKeyNode) {
    publicKeyNode.publicKeyBase58 = this.publicKeyBase58;
    return publicKeyNode;
  }

  /**
   * Adds an encrypted private key to the KeyPair.
   * @param {Object} keyNode - A plain object.
   *
   * @return {Object} The keyNode with an encrypted private key attached.
   */
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
   * Produces a 32-byte encrypted key.
   * @example
   * > const encryptedContent = await edKeyPair
   *   .encrypt(privateKey, 'Test1244!');
   * @param {string} privateKey - The base58 private key.
   * @param {string} password - The password.
   *
   * @returns {Promise<JWE>} Produces JSON Web encrypted content.
   * @see [JWE]{@link ./index.md#JWE}
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

  /**
   * Decrypts jwe content to a privateKey.
   * @param {JWE} jwe - Encrypted content from a block.
   * @param {string} password - Password for the key used to sign the content.
   *
   * @returns {Object} A Base58 private key.
   * @see [JWE]{@link ./index.md#JWE}
   */
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
   * Generates and returns a multiformats encoded
   * ed25519 public key fingerprint (for use with cryptonyms, for example).
   * @example
   * > edKeyPair.fingerprint();
   * z6dfdsfdsfds3432423
   * @see https://github.com/multiformats/multicodec
   *
   * @returns {string} A verifiable cryptographic signature.
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

    // prefix with `z` to indicate multi-base base58btc encoding
    return `z${base58.encode(buffer)}`;
  }

  /**
   * Tests whether the fingerprint was
   * generated from a given key pair.
   * @example
   * > edKeyPair.verifyFingerprint('z2S2Q6MkaFJewa');
   * {valid: true};
   * @param {string} fingerprint - A Base58 public key.
   *
   * @returns {Object} An object indicating valid is true or false.
   */
  verifyFingerprint(fingerprint) {
    // fingerprint should have `z` prefix indicating
    // that it's multi-base encoded
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
 * @ignore
 * Returns an object with an async sign function.
 * The sign function is bound to the KeyPair
 * and then returned by the KeyPair's signer method.
 * @param {Ed25519KeyPair} key - An ED25519KeyPair.
 * @example
 * > const mySigner = ed25519SignerFactory(edKeyPair);
 * > await mySigner.sign({data})
 *
 * @returns {{sign: Function}} An object with an async function sign
 * using the private key passed in.
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
 * @ignore
 * Returns an object with an async verify function.
 * The verify function is bound to the KeyPair
 * and then returned by the KeyPair's verifier method.
 * @param {Ed25519KeyPair} key - An Ed25519KeyPair.
 * @example
 * > const myVerifier = ed25519Verifier(edKeyPair);
 * > await myVerifier.verify({data, signature});
 *
 * @returns {{verify: Function}} An async verifier specific
 * to the key passed in.
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
 * Wraps Base58 decoding operations in
 * order to provide consistent error messages.
 * @ignore
 * @example
 * > const pubkeyBytes = _base58Decode({
 *    decode: base58.decode,
 *    keyMaterial: this.publicKeyBase58,
 *    type: 'public'
 *   });
 * @param {Object} options - The decoder options.
 * @param {Function} options.decode - The decode function to use.
 * @param {string} options.keyMaterial - The Base58 encoded
 * key material to decode.
 * @param {string} options.type - A description of the
 * key material that will be included
 * in an error message (e.g. 'public', 'private').
 *
 * @returns {Object} - The decoded bytes. The data structure for the bytes is
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
