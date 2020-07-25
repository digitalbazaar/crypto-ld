/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const chai = require('chai');
chai.should();
const {expect} = chai;

const {CryptoLD} = require('../../lib');

describe('CryptoLD', () => {
  let cryptoLd;
  beforeEach(() => {
    cryptoLd = new CryptoLD();
  });

  describe('constructor', async () => {
    it('should init a custom suite map', async () => {
      const suites = {};
      cryptoLd = new CryptoLD({suites});

      expect(cryptoLd.suites).to.equal(suites);
    });
  });

  describe('use()', () => {
    it('should install library driver for suite', async () => {
      const keyLibrary = {type: 'Ed25519VerificationKey2018'};

      cryptoLd.use(keyLibrary);

      expect(cryptoLd._installed({type: 'Ed25519VerificationKey2018'}))
        .to.equal(true);
    });
  });

  describe('generate()', () => {
    it('should error on missing type', async () => {
      let error;
      try {
        await cryptoLd.generate();
      } catch(e) {
        error = e;
      }
      expect(error.message).to
        .equal('A key type is required to generate.');
    });

    it('should error on unsupported type', async () => {
      let error;
      try {
        await cryptoLd.generate({type: 'Ed25519VerificationKey2018'});
      } catch(e) {
        error = e;
      }
      expect(error.message).to
        .match(/Support for key type "Ed25519VerificationKey2018"/);
    });

    it('should generate based on key type', async () => {
      const keyLibrary = {
        type: 'Ed25519VerificationKey2018',
        generate: async options => options
      };
      cryptoLd.use(keyLibrary);
      const result = await cryptoLd.generate({
        type: 'Ed25519VerificationKey2018', controller: 'did:ex:1234'
      });
      expect(result).to.eql({controller: 'did:ex:1234'});
    });
  });

  describe('from()', () => {
    it('should error on missing type param', async () => {
      let error;
      try {
        await cryptoLd.from({});
      } catch(e) {
        error = e;
      }
      expect(error.message).to.equal('Missing key type.');
    });

    it('should error on uninstalled key type', async () => {
      let error;
      try {
        await cryptoLd.from({type: 'Ed25519VerificationKey2018'});
      } catch(e) {
        error = e;
      }
      expect(error.message).to
        .equal(
          'Support for key type "Ed25519VerificationKey2018" is not installed.'
        );
    });

    it('should return an instance from serialized data', async () => {
      const keyLibrary = {
        type: 'Ed25519VerificationKey2018',
        from: async data => data
      };
      cryptoLd.use(keyLibrary);

      const serializedKey = {
        type: 'Ed25519VerificationKey2018'
      };

      const result = await cryptoLd.from(serializedKey);

      expect(result).to.equal(serializedKey);
    });
  });
});
