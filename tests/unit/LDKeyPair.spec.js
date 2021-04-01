/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const chai = require('chai');
chai.should();
const {expect} = chai;

const {LDKeyPair} = require('../../lib');

describe('LDKeyPair', () => {
  let keyPair;
  beforeEach(() => {
    keyPair = new LDKeyPair();
  });

  describe('constructor', () => {
    it('should initialize id and controller', async () => {
      const controller = 'did:ex:1234';
      const id = 'did:ex:1234#fingerprint';
      const keyPair = new LDKeyPair({id, controller});

      expect(keyPair.id).to.equal(id);
      expect(keyPair.controller).to.equal(controller);
    });
  });

  describe('generate()', () => {
    it('should throw an abstract method error', async () => {
      let error;

      try {
        await LDKeyPair.generate();
      } catch(e) {
        error = e;
      }
      expect(error.message).to.match(/Abstract method/);
    });
  });

  describe('from()', () => {
    it('should throw an abstract method error', async () => {
      let error;

      try {
        await LDKeyPair.from();
      } catch(e) {
        error = e;
      }
      expect(error.message).to.match(/Abstract method/);
    });
  });

  describe('fingerprint()', () => {
    it('should throw an abstract method error', async () => {
      expect(() => keyPair.fingerprint()).to.throw(/Abstract method/);
    });
  });

  describe('verifyFingerprint()', () => {
    it('should throw an abstract method error', async () => {
      expect(() => keyPair.verifyFingerprint('z1234'))
        .to.throw(/Abstract method/);
    });
  });

  describe('export()', () => {
    it('should error if neither private or public key specified', async () => {
      expect(() => {
        keyPair.export();
      }).to.throw(/Export requires/);
    });
  });

  describe('signer()', () => {
    it('should return an abstract signer function', async () => {
      const vKeyPair = new LDKeyPair();

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
      const vKeyPair = new LDKeyPair();

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

  describe('fromKeyDocument()', async () => {
    const EXAMPLE_KEY_DOCUMENT = {
      id: 'did:example:1234#z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3',
      controller: 'did:example:1234',
      type: 'Ed25519VerificationKey2020',
      publicKeyMultibase: 'zEYJrMxWigf9boyeJMTRN4Ern8DJMoCXaLK77pzQmxVjf'
    };

    it('should error on missing keyId', async () => {
      let error;
      try {
        await LDKeyPair.fromKeyDocument();
      } catch(e) {
        error = e;
      }
      expect(error).to.exist;
      expect(error.message).to.equal('The "document" parameter is required.');
    });

    it('should invoke the suite from() method', async () => {
      const keyDocument = {...EXAMPLE_KEY_DOCUMENT};
      let error;
      try {
        await LDKeyPair.fromKeyDocument({document: keyDocument,
          checkContext: false, checkRevoked: false});
      } catch(e) {
        error = e;
      }
      expect(error).to.exist;
      expect(error.message).to
        .equal('Abstract method from() must be implemented in subclass.');
    });

    it('should error on failed context check', async () => {
      const keyDocument = {...EXAMPLE_KEY_DOCUMENT};
      let error;
      try {
        await LDKeyPair.fromKeyDocument({document: keyDocument,
          checkContext: true});
      } catch(e) {
        error = e;
      }
      expect(error).to.exist;

      expect(error.message).to
        // eslint-disable-next-line max-len
        .equal('Key document does not contain required context "INVALID LDKeyPair CONTEXT".');
    });

    it('should error on failed revoked check', async () => {
      const pastDate = new Date(2020, 11, 17).toISOString()
        .replace(/\.[0-9]{3}/, '');
      const keyDocument = {
        ...EXAMPLE_KEY_DOCUMENT,
        revoked: pastDate};
      let error;
      try {
        await LDKeyPair.fromKeyDocument({document: keyDocument,
          checkContext: false, checkRevoked: true});
      } catch(e) {
        error = e;
      }
      expect(error).to.exist;
      expect(error.message).to.contain('revoked');
      expect(error.message).to.contain(pastDate);
    });
  });
});
