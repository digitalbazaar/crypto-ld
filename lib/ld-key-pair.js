/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const env = require('./env');

const forge = require('node-forge');
const base64url = require('base64url');

const DEFAULT_RSA_KEY_BITS = 2048;
const DEFAULT_RSA_EXPONENT = 0x10001;

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
    throw new Error('Abstract method, must be implemented in subclass.')
  }

  /**
   * Returns subclass-appropriate private key material.
   */
  get privateKey() {
    throw new Error('Abstract method, must be implemented in subclass.')
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
        return Ed25519KeyPair.generate(options);

      case 'RsaVerificationKey2018':
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
        return Ed25519KeyPair.from(options);

      case 'RsaVerificationKey2018':
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
    // TODO: use native node crypto api once it's available
    const sodium = require('sodium-universal');

    if(env.nodejs) {
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

    const publicKey = new Uint8Array(sodium.crypto_sign_PUBLICKEYBYTES);
    const privateKey = new Uint8Array(sodium.crypto_sign_SECRETKEYBYTES);
    sodium.crypto_sign_keypair(publicKey, privateKey);
    return new Ed25519KeyPair({
      publicKeyBase58: forge.util.binary.base58.encode(publicKey),
      privateKeyBase58: forge.util.binary.base58.encode(privateKey),
      ...options
    });
  }

  static async from(options) {
    const privateKeyBase58 = options.privateKeyBase58 ||
      (options.privateKey && options.privateKey.privateKeyBase58); // legacy privateDidDoc format
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
    const pubkeyBytes = forge.util.binary.base58.decode(this.publicKeyBase58);
    buffer.putBytes(forge.util.hexToBytes('ed01'));
    buffer.putBytes(pubkeyBytes.toString('binary'));

    // prefix with `z` to indicate multibase base58btc encoding
    return `z${forge.util.binary.base58.encode(buffer)}`;
  }

  /**
   * Tests whether the fingerprint was generated from a given key pair.
   *
   * @param fingerprint {string}
   *
   * @returns {boolean}
   */
  verifyFingerprint(fingerprint) {
    const fingerprintBuffer = forge.util.binary.base58.decode(fingerprint);
    const publicKeyBuffer = forge.util.binary.base58.decode(
      this.publicKeyBase58);

    // validate the first two multicodec bytes 0xed01
    return fingerprintBuffer.slice(0, 2).toString('hex') === 'ed01' &&
      publicKeyBuffer.equals(fingerprintBuffer.slice(2));
  }
}

class RSAKeyPair extends LDKeyPair {
  constructor(options = {}) {
    super(options);
    this.type = 'RsaVerificationKey2018';
    this.privateKeyPem = options.privateKeyPem;
    this.publicKeyPem = options.publicKeyPem;

    this.validateKeyParams(); // validate keyBits and exponent
  }

  get publicKey() {
    return this.publicKeyPem;
  }

  get privateKey() {
    return this.privateKeyPem;
  }

  /**
   * @param options
   * @returns {Promise<RSAKeyPair>}
   */
  static async generate(options = {}) {
    if(env.nodejs) {
      const {generateKeyPair} = require('crypto');
      // node >= 10.12.0
      if(generateKeyPair) {
        const {promisify} = require('util');
        const pGenerateKeyPair = promisify(generateKeyPair);
        const key = await pGenerateKeyPair('rsa', {
          modulusLength: DEFAULT_RSA_KEY_BITS,
          publicExponent: DEFAULT_RSA_EXPONENT,
          publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
          },
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
          }
        });
        return new RSAKeyPair({
          publicKeyPem: key.publicKey,
          privateKeyPem: key.privateKey,
          ...options
        });
      }
    }

    // browsers and node < 10.12.0
    return new Promise((resolve, reject) => {
      forge.pki.rsa.generateKeyPair(
        {
          bits: DEFAULT_RSA_KEY_BITS,
          e: DEFAULT_RSA_EXPONENT,
          workers: -1
        },
        (err, keyPair) => {
          if(err) {
            return reject(err);
          }
          resolve(new RSAKeyPair({
            publicKeyPem: forge.pki.publicKeyToPem(keyPair.publicKey),
            privateKeyPem: forge.pki.privateKeyToPem(keyPair.privateKey),
            ...options
          }));
        });
    });
  }

  static async from(options) {
    const privateKeyPem = options.privateKeyPem ||
      (options.privateKeyPem && options.privateKey.privateKeyPem); // legacy privateDidDoc format

    const keys = new RSAKeyPair({
      publicKey: options.publicKeyPem,
      privateKeyPem,
      type: options.type || options.keyType, // todo: deprecate keyType usage
      ...options
    });

    return keys;
  }

  validateKeyParams() {
    if(this.publicKeyPem) {
      const publicKey = forge.pki.publicKeyFromPem(this.publicKeyPem);
      const keyBits = publicKey.n.bitLength();
      if(keyBits !== DEFAULT_RSA_KEY_BITS) {
        throw new Error(`Invalid RSA keyBit length ${JSON.stringify(keyBits)}` +
          ` required value is ${DEFAULT_RSA_KEY_BITS}`);
      }
      if(publicKey.e.toString(10) !== '65537') {
        throw new Error(`Invalid RSA exponent ${JSON.stringify(publicKey.e.toString(10))}` +
          ` required value is 65537}`);
      }
    }

    if(this.privateKeyPem) {
      const privateKey = forge.pki.privateKeyFromPem(this.privateKeyPem);
      const keyBits = privateKey.n.bitLength();
      if(keyBits !== DEFAULT_RSA_KEY_BITS) {
        throw new Error(`Invalid RSA keyBit length ${JSON.stringify(keyBits)}` +
          ` required value is ${DEFAULT_RSA_KEY_BITS}`);
      }
      if(privateKey.e.toString(10) !== '65537') {
        throw new Error(`Invalid RSA exponent ${JSON.stringify(privateKey.e.toString(10))}` +
          ` required value is 65537}`);
      }
    }
  }

  addEncodedPublicKey(publicKeyNode) {
    publicKeyNode.publicKeyPem = this.publicKeyPem;
    return publicKeyNode;
  }

  async addEncryptedPrivateKey(keyNode) {
    if(this.passphrase !== null) {
      keyNode.privateKeyPem = forge.pki.encryptRsaPrivateKey(
        forge.pki.privateKeyFromPem(this.privateKeyPem),
        this.passphrase,
        {algorithm: 'aes256'}
      );
    } else {
      // no passphrase, do not encrypt private key
      keyNode.privateKeyPem = this.privateKeyPem;
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
    const buffer = forge.util.createBuffer();

    // use SubjectPublicKeyInfo fingerprint
    const fingerprintBuffer = forge.pki.getPublicKeyFingerprint(
      forge.pki.publicKeyFromPem(this.publicKeyPem), {md: forge.md.sha256.create()});
    // RSA cryptonyms are multiformat encoded values, specifically they are:
    // (multicodec 0x30 + rsa-pub-fingerprint 0x5a + multihash 0x31 +
    //  sha2-256 0x12 + 32 byte value 0x20)
    buffer.putBytes(forge.util.hexToBytes('305a311220'));
    buffer.putBytes(fingerprintBuffer.bytes());

    return forge.util.binary.base58.encode(buffer);
  }

  /**
   * Returns a signer object for use with jsonld-signatures.
   *
   * @returns {{sign: function}}
   */
  signer() {
    return rsaSignerFactory(this);
  }

  /**
   * Returns a verifier object for use with jsonld-signatures.
   *
   * @returns {{verify: function}}
   */
  verifier() {
    return rsaVerifierFactory(this);
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
    const sodium = require('sodium-universal');
    const bs58 = require('bs58');
    const privateKey = bs58.decode(key.privateKeyBase58);
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
  const privateKey = forge.util.binary.base58.decode(key.privateKeyBase58);
  return {
    async sign({data}) {
      return forge.ed25519.sign({message: data, privateKey});
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
    const sodium = require('sodium-universal');
    const bs58 = require('bs58');
    const publicKey = bs58.decode(key.publicKeyBase58);
    return {
      async verify({data, signature}) {
        return sodium.crypto_sign_verify_detached(
          Buffer.from(signature.buffer, signature.byteOffset, signature.length),
          Buffer.from(data.buffer, data.byteOffset, data.length),
          publicKey);
      }
    };
  }
  const publicKey = forge.util.binary.base58.decode(key.publicKeyBase58);
  return {
    async verify({data, signature}) {
      return forge.ed25519.verify({message: data, signature, publicKey});
    }
  };
}

/**
 * Returns a signer object for use with jsonld-signatures.
 *
 * @returns {{sign: function}}
 */
function rsaSignerFactory(key) {
  if(!key.privateKeyPem) {
    return {
      async sign() {
        throw new Error('No private key to sign with.');
      }
    };
  }

  // Note: Per rfc7518, the digest algorithm for PS256 is SHA-256,
  // https://tools.ietf.org/html/rfc7518

  // sign data using RSASSA-PSS where PSS uses a SHA-256 hash,
  // a SHA-256 based masking function MGF1, and a 32 byte salt to match
  // the hash size
  if(env.nodejs) {
    // node.js 8+
    const crypto = require('crypto');
    if('RSA_PKCS1_PSS_PADDING' in crypto.constants) {
      return {
        async sign({data}) {
          const signer = crypto.createSign('RSA-SHA256');
          signer.update(Buffer.from(data.buffer, data.byteOffset, data.length));
          const buffer = signer.sign({
            key: key.privateKeyPem,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
          });
          return new Uint8Array(
            buffer.buffer, buffer.byteOffset, buffer.length);
        }
      };
    }
  }

  // browser or other environment (including node 6.x)
  const privateKey = forge.pki.privateKeyFromPem(key.privateKeyPem);
  return {
    async sign({data}) {
      const pss = createPss();
      const md = forge.md.sha256.create();
      md.update(forge.util.binary.raw.encode(data), 'binary');
      const binaryString = privateKey.sign(md, pss);
      return forge.util.binary.raw.decode(binaryString);
    }
  };
}

function rsaVerifierFactory(key) {
  if(env.nodejs) {
    // node.js 8+
    const crypto = require('crypto');
    if('RSA_PKCS1_PSS_PADDING' in crypto.constants) {
      return {
        async verify({data, signature}) {
          const verifier = crypto.createVerify('RSA-SHA256');
          verifier.update(
            Buffer.from(data.buffer, data.byteOffset, data.length));
          return verifier.verify({
            key: key.publicKeyPem,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
          }, Buffer.from(
            signature.buffer, signature.byteOffset, signature.length));
        }
      };
    }
  }

  // browser or other environment (including node 6.x)
  const publicKey = forge.pki.publicKeyFromPem(key.publicKeyPem);
  return {
    async verify({data, signature}) {
      const pss = createPss();
      const md = forge.md.sha256.create();
      md.update(forge.util.binary.raw.encode(data), 'binary');
      try {
        return publicKey.verify(
          md.digest().bytes(),
          forge.util.binary.raw.encode(signature),
          pss);
      } catch(e) {
        // simply return false, do return information about malformed signature
        return false;
      }
    }
  };
}

function createPss() {
  const md = forge.md.sha256.create();
  return forge.pss.create({
    md,
    mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
    saltLength: md.digestLength
  });
}

module.exports = {
  LDKeyPair,
  Ed25519KeyPair,
  RSAKeyPair,
  ed25519SignerFactory,
  ed25519VerifierFactory,
  rsaSignerFactory,
  rsaVerifierFactory,
  createPss
};
