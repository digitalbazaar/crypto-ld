/*!
 * Copyright (c) 2018-2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const env = require('./env');
const forge = require('node-forge');
const {
  md: {sha256},
  pki: {getPublicKeyFingerprint, publicKeyFromPem},
  util: {binary: {base58, raw}}
} = forge;
const LDKeyPair = require('./LDKeyPair');

const DEFAULT_RSA_KEY_BITS = 2048;
const DEFAULT_RSA_EXPONENT = 0x10001;

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
    // forge will use a native implementation in nodejs >= 10.12.0
    // and a purejs implementation in browser and nodejs < 10.12.0
    return new Promise((resolve, reject) => {
      forge.pki.rsa.generateKeyPair({
        bits: DEFAULT_RSA_KEY_BITS,
        e: DEFAULT_RSA_EXPONENT,
        workers: -1
      }, (err, keyPair) => {
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
      // legacy privateDidDoc format
      (options.privateKeyPem && options.privateKey.privateKeyPem);

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
        throw new Error(
          `Invalid RSA exponent ${JSON.stringify(publicKey.e.toString(10))}` +
          ' required value is 65537}');
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
        throw new Error(
          `Invalid RSA exponent ${JSON.stringify(privateKey.e.toString(10))}` +
          ' required value is 65537}');
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
      forge.pki.publicKeyFromPem(this.publicKeyPem),
      {md: sha256.create()});
    // RSA cryptonyms are multiformat encoded values, specifically they are:
    // (multicodec RSA SPKI-based public key 0x5d + sha2-256 0x12 +
    // 32 byte value 0x20)
    buffer.putBytes(forge.util.hexToBytes('5d1220'));
    buffer.putBytes(fingerprintBuffer.bytes());

    // prefix with `z` to indicate multibase base58btc encoding
    return `z${base58.encode(buffer)}`;
  }

  /*
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
    // base58.decode returns Buffer(nodejs) or Uint8Array
    const fingerprintBuffer = base58.decode(fingerprint.slice(1));
    // keyFingerprintBuffer is a forge ByteStringBuffer
    const keyFingerprintBuffer = getPublicKeyFingerprint(
      publicKeyFromPem(this.publicKeyPem), {md: sha256.create()});

    // validate the first three multicodec bytes 0x5d1220
    const valid = fingerprintBuffer.slice(0, 3).toString('hex') === '5d1220' &&
      keyFingerprintBuffer.toHex() ===
      fingerprintBuffer.slice(3).toString('hex');
    if(!valid) {
      return {
        error: new Error('The fingerprint does not match the public key.'),
        valid: false
      };
    }

    return {valid};
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
      const md = sha256.create();
      md.update(raw.encode(data), 'binary');
      const binaryString = privateKey.sign(md, pss);
      return raw.decode(binaryString);
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
  const publicKey = publicKeyFromPem(key.publicKeyPem);
  return {
    async verify({data, signature}) {
      const pss = createPss();
      const md = sha256.create();
      md.update(raw.encode(data), 'binary');
      try {
        return publicKey.verify(
          md.digest().bytes(),
          raw.encode(signature),
          pss);
      } catch(e) {
        // simply return false, do return information about malformed signature
        return false;
      }
    }
  };
}

function createPss() {
  const md = sha256.create();
  return forge.pss.create({
    md,
    mgf: forge.mgf.mgf1.create(sha256.create()),
    saltLength: md.digestLength
  });
}

module.exports = RSAKeyPair;
