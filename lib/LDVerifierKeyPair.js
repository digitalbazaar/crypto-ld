/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {LDKeyPair} = require('./LDKeyPair');

/**
 * @abstract
 */
class LDVerifierKeyPair extends LDKeyPair {
  /* eslint-disable max-len */
  /**
   * Returns a signer object for use with
   * [jsonld-signatures]{@link https://github.com/digitalbazaar/jsonld-signatures}.
   * @abstract
   * @example
   * > const signer = keyPair.signer();
   * > signer
   * { sign: [AsyncFunction: sign] }
   * > signer.sign({data});
   *
   * @returns {{sign: Function}} A signer for json-ld usage.
   */
  /* eslint-enable */
  signer() {
    return {
      async sign({/* data */}) {
        throw new Error('Abstract method, must be implemented in subclass.');
      }
    };
  }

  /* eslint-disable max-len */
  /**
   * Returns a verifier object for use with
   * [jsonld-signatures]{@link https://github.com/digitalbazaar/jsonld-signatures}.
   * @abstract
   * @example
   * > const verifier = keyPair.verifier();
   * > verifier
   * { verify: [AsyncFunction: verify] }
   * > verifier.verify(key);
   *
   * @returns {{verify: Function}} Used to verify jsonld-signatures.
   */
  /* eslint-enable */
  verifier() {
    return {
      async verify({/* data, signature */}) {
        throw new Error('Abstract method, must be implemented in subclass.');
      }
    };
  }
}

module.exports = {
  LDVerifierKeyPair
};
