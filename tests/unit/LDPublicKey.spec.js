/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const chai = require('chai');
chai.should();
const {expect} = chai;

const {LDPublicKey} = require('../../lib');

describe('LDPublicKey', () => {
  let publicKey;
  beforeEach(() => {
    publicKey = new LDPublicKey();
  });

  describe('constructor', () => {
    it('should initialize id and controller', async () => {
      const controller = 'did:ex:1234';
      const id = 'did:ex:1234#fingerprint';
      const publicKey = new LDPublicKey({id, controller});

      expect(publicKey.id).to.equal(id);
      expect(publicKey.controller).to.equal(controller);
    });
  });

  describe('generate()', () => {
    it('should throw an abstract method error', async () => {
      let error;

      try {
        await LDPublicKey.generate();
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
        await LDPublicKey.from();
      } catch(e) {
        error = e;
      }
      expect(error.message).to.match(/Abstract method/);
    });
  });

  describe('addPublicKey()', () => {
    it('should throw an abstract method error', async () => {
      expect(() => publicKey.addPublicKey()).to.throw(/Abstract method/);
    });
  });

  describe('fingerprint()', () => {
    it('should throw an abstract method error', async () => {
      expect(() => publicKey.fingerprint()).to.throw(/Abstract method/);
    });
  });

  describe('verifyFingerprint()', () => {
    it('should throw an abstract method error', async () => {
      expect(() => publicKey.verifyFingerprint('z1234'))
        .to.throw(/Abstract method/);
    });
  });

  describe('export()', () => {
    it('should export just the public key serialization', async () => {
      publicKey.controller = 'did:ex:1234';
      publicKey.id = 'did:ex:1234#fingerprint';
      publicKey.type = 'ExampleVerificationKey2020';
      const encodedPublicKey = 'encoded public key';

      publicKey.addPublicKey = ({key}) => {
        key.publicKeyMultibase = encodedPublicKey;
        return key;
      };

      expect(publicKey.export({publicKey: true})).to.eql({
        controller: 'did:ex:1234',
        id: 'did:ex:1234#fingerprint',
        publicKeyMultibase: 'encoded public key',
        type: 'ExampleVerificationKey2020'
      });
    });
  });
});
