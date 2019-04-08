/*
 * Copyright (c) 2018-2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {util: {binary: {base58}}} = require('node-forge');

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
exports.base58Decode = ({decode, keyMaterial, type}) => {
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
};

/**
 * Generates and returns a multiformats encoded
 * ed25519 public key fingerprint (for use with cryptonyms, for example).
 * @see https://github.com/multiformats/multicodec
 *
 * @param {string} keyMaterial - The base58 encoded public key material.
 *
 * @returns {string} The fingerprint.
 */
exports.base58PublicKeyFingerprint = ({keyMaterial}) => {
  // ed25519 cryptonyms are multicodec encoded values, specifically:
  // (multicodec ed25519-pub 0xed01 + key bytes)
  const pubkeyBytes = exports.base58Decode({
    decode: base58.decode,
    keyMaterial,
    type: 'public'
  });
  const buffer = new Uint8Array(2 + pubkeyBytes.length);
  buffer[0] = 0xed;
  buffer[1] = 0x01;
  buffer.set(pubkeyBytes, 2);
  // prefix with `z` to indicate multi-base base58btc encoding
  return `z${base58.encode(buffer)}`;
};
