/*!
 * Copyright (c) 2018-2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {Ed25519KeyPair} = require('..');
const mockKey = require('./mock-key');

const keyPair = new Ed25519KeyPair({
  publicKeyBase58: mockKey.publicKeyBase58,
  privateKeyBase58: mockKey.privateKeyBase58
});

const signer = keyPair.signer();
const verifier = keyPair.verifier();

// the same signature should be generated on every test platform
// (eg. browser, node8, node12)
const targetSignatureBase64 = 'nlQC1bVF6TMN6cAEJllRGK5orHm5+n4Ih46mu' +
  'RYgQhTl8J9SR82fEPq7IEAmT9GprBrcRKJzxUk0Eo+yU92zCg==';

describe('sign and verify', () => {
  it('works properly', async () => {
    const data = Buffer.from('test 1234');
    const signature = await signer.sign({data});
    signature.toString('base64').should.equal(targetSignatureBase64);
    const result = await verifier.verify({data, signature});
    result.should.be.true;
  });
  it('fails if signing data is changed', async () => {
    const data = Buffer.from('test 1234');
    const signature = await signer.sign({data});
    const changedData = Buffer.from('test 4321');
    const result = await verifier.verify({data: changedData, signature});
    result.should.be.false;
  });
});
