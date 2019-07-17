/*!
 * Copyright (c) 2018-2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {util: {binary: {base58}}} = require('node-forge');
const {_derEncode: privateDerEncode} =
  require('../lib/ed25519PrivateKeyNode12');
const {_derEncode: publicDerEncode} = require('../lib/ed25519PublicKeyNode12');
const util = require('../lib/util');
const mockKey = require('./mock-key');

const targetPrivateDerBytesBase64 =
  'MC4CAQAwBQYDK2VwBCIEICuAHzsgGqFh8BWmT1iucnc0w4mS5KfnfnaOtHG6yWuA';
const targetPublicDerBytesBase64 =
  'MCowBQYDK2VwAyEAvHZI57pFMs4OnJfkcp0QSotH9LbDT/6yRtYKt/ZpUpU=';

const privateKeyBytes = util.base58Decode({
  decode: base58.decode,
  keyMaterial: mockKey.privateKeyBase58,
  type: 'private'
});

const publicKeyBytes = util.base58Decode({
  decode: base58.decode,
  keyMaterial: mockKey.publicKeyBase58,
  type: 'public'
});

describe('Ed25519 Keys', () => {
  describe('Ed25519 Private Key', () => {
    describe('DER encoding', () => {
      it('works properly', async () => {
        const forgeDer = privateDerEncode({privateKeyBytes});
        const forgeDerBytesBase64 = Buffer.from(forgeDer).toString('base64');
        forgeDerBytesBase64.should.equal(targetPrivateDerBytesBase64);
      });
    }); // end DER encoding
  }); // end Ed25519 Private Key

  describe('Ed25519 Public Key', () => {
    describe('DER encoding', () => {
      it('works properly', async () => {
        const forgeDer = publicDerEncode({publicKeyBytes});
        const forgeDerBytesBase64 = Buffer.from(forgeDer).toString('base64');
        forgeDerBytesBase64.should.equal(targetPublicDerBytesBase64);
      });
    }); // end DER encoding
  }); // end Ed25519 Private Key
});

// export DERs from Node public and private keys to use as test vectors
/*
async function _generateTestVector() {
  const {createPublicKey} = require('crypto');
  const _privateKey = require('../lib/ed25519PrivateKeyNode12');

  // create a node private key
  const privateKey = _privateKey.create({privateKeyBytes});

  // create a node public key from the private key
  const publicKey = createPublicKey(privateKey);

  // export the keys and extract key bytes from the exported DERs
  const publicKeyEncoding = {format: 'der', type: 'spki'};
  const privateKeyEncoding = {format: 'der', type: 'pkcs8'};
  const publicKeyDerBytes = Buffer.from(publicKey.export(publicKeyEncoding));
  const privateKeyDerBytes = Buffer.from(privateKey.export(privateKeyEncoding));
  publicKeyDerBytes.toString('base64').should.equal(targetPublicDerBytesBase64);
  privateKeyDerBytes.toString('base64').should.equal(
    targetPrivateDerBytesBase64);
}
*/
