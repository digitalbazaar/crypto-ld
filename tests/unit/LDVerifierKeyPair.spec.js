/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const chai = require('chai');
chai.should();
const {expect} = chai;

const {LDVerifierKeyPair} = require('../../lib');

describe('LDVerifierKeyPair', () => {
  describe('signer()', () => {
    it('should return an abstract signer function', async () => {
      const vKeyPair = new LDVerifierKeyPair();

      const {sign} = vKeyPair.signer();
      let error;

      try {
        await sign({data: 'test data'});
      } catch(e) {
        error = e;
      }

      expect(error.message).to.match(/Abstract method/);
    });
  });

  describe('verifier()', () => {
    it('should return an abstract verifier function', async () => {
      const vKeyPair = new LDVerifierKeyPair();

      const {verify} = vKeyPair.verifier();
      const key = {};
      const signature = 'test signature';
      let error;

      try {
        await verify({key, signature});
      } catch(e) {
        error = e;
      }

      expect(error.message).to.match(/Abstract method/);
    });
  });
});
