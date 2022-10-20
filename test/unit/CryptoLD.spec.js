/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
chai.should();
const {expect} = chai;

import {CryptoLD} from '../../lib/index.js';

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
      const keyLibrary = {suite: 'Ed25519VerificationKey2018'};

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
        .equal('Missing key type.');
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
      const Suite = {
        suite: 'Ed25519VerificationKey2018',
        generate: async options => options
      };
      cryptoLd.use(Suite);
      const result = await cryptoLd.generate({
        type: 'Ed25519VerificationKey2018', controller: 'did:ex:1234'
      });
      expect(result).to.eql({
        controller: 'did:ex:1234', type: 'Ed25519VerificationKey2018'
      });
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
      const Suite = {
        suite: 'Ed25519VerificationKey2018',
        from: async data => data
      };
      cryptoLd.use(Suite);

      const serializedKey = {
        type: 'Ed25519VerificationKey2018'
      };

      const result = await cryptoLd.from(serializedKey);

      expect(result).to.equal(serializedKey);
    });
  });

  describe('fromKeyId()', () => {
    const EXAMPLE_KEY_DOCUMENT = {
      id: 'did:example:1234#z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3',
      controller: 'did:example:1234',
      type: 'Ed25519VerificationKey2020',
      publicKeyMultibase: 'zEYJrMxWigf9boyeJMTRN4Ern8DJMoCXaLK77pzQmxVjf'
    };

    it('should error on missing keyId', async () => {
      let error;
      try {
        await cryptoLd.fromKeyId();
      } catch(e) {
        error = e;
      }
      expect(error).to.exist;
      expect(error.message).to.equal('The "id" parameter is required.');
    });

    it('should error on missing documentLoader', async () => {
      let error;
      try {
        await cryptoLd.fromKeyId({id: 'did:ex:123#fingerprint'});
      } catch(e) {
        error = e;
      }
      expect(error).to.exist;
      expect(error.message).to
        .equal('The "documentLoader" parameter is required.');
    });

    it('error if documentLoader is not properly implemented', async () => {
      const keyDocument = {
        ...EXAMPLE_KEY_DOCUMENT, type: 'ExampleKeySuite202X'
      };
      const keyId = keyDocument.id;
      const documentLoader = async url => {
        return {
          url,
          // a properly implemented loader returns `document` not `doc`
          doc: keyDocument
        };
      };

      let error;
      try {
        await cryptoLd.fromKeyId({id: keyId, documentLoader});
      } catch(e) {
        error = e;
      }
      expect(error).to.exist;
      expect(error.message).to.contain('function must return');
      expect(error.cause.message).to.contain('function must return');
    });

    it('error if key document not found via documentLoader', async () => {
      const keyDocument = {...EXAMPLE_KEY_DOCUMENT};
      const keyId = keyDocument.id;
      const documentLoader = async () => {
        throw new Error('Example fetching error.');
      };

      let error;
      try {
        await cryptoLd.fromKeyId({id: keyId, documentLoader});
      } catch(e) {
        error = e;
      }
      expect(error).to.exist;
      expect(error.message).to
        .equal('Error fetching document: Example fetching error.');
      expect(error.cause.message).to
        .equal('Example fetching error.');
    });

    it('should error if key suite was not installed', async () => {
      const keyDocument = {...EXAMPLE_KEY_DOCUMENT};
      const keyId = keyDocument.id;
      const documentLoader = async url => {
        return {
          url,
          document: keyDocument
        };
      };

      let error;
      try {
        await cryptoLd.fromKeyId({id: keyId, documentLoader});
      } catch(e) {
        error = e;
      }
      expect(error).to.exist;
      expect(error.message).to.equal(
        'Support for suite "Ed25519VerificationKey2020" is not installed.');
    });

    it('should return key pair via a suite `fromKeyDocument()`', async () => {
      const mockKeyPair = {};
      const keyDocument = {
        ...EXAMPLE_KEY_DOCUMENT, type: 'ExampleKeySuite202X'
      };
      const keyId = keyDocument.id;
      const documentLoader = async url => {
        return {
          url,
          document: keyDocument
        };
      };
      const ExampleKeySuite202X = {};
      ExampleKeySuite202X.suite = 'ExampleKeySuite202X';
      ExampleKeySuite202X.fromKeyDocument = async () => {
        return mockKeyPair;
      };

      cryptoLd.use(ExampleKeySuite202X);
      const result = await cryptoLd.fromKeyId({id: keyId, documentLoader});
      expect(result).to.equal(mockKeyPair);
    });
  });
});
