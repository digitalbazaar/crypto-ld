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

  describe('addPublicKey()', () => {
    it('should throw an abstract method error', async () => {
      expect(() => keyPair.addPublicKey()).to.throw(/Abstract method/);
    });
  });

  describe('addPrivateKey()', () => {
    it('should throw an abstract method error', async () => {
      expect(() => keyPair.addPrivateKey()).to.throw(/Abstract method/);
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

    it('should export just the public key serialization', async () => {
      keyPair.controller = 'did:ex:1234';
      keyPair.id = 'did:ex:1234#fingerprint';
      keyPair.type = 'ExampleVerificationKey2020';
      const encodedPublicKey = 'encoded public key';

      keyPair.addPublicKey = ({key}) => {
        key.publicKeyBase58 = encodedPublicKey;
        return key;
      };
      keyPair.addPrivateKey = () => {
        throw new Error('Should not be exported');
      };

      expect(keyPair.export({publicKey: true})).to.eql({
        controller: 'did:ex:1234',
        id: 'did:ex:1234#fingerprint',
        publicKeyBase58: 'encoded public key',
        type: 'ExampleVerificationKey2020'
      });
    });

    it('should export just the public key serialization', async () => {
      keyPair.controller = 'did:ex:1234';
      keyPair.id = 'did:ex:1234#fingerprint';
      keyPair.type = 'ExampleVerificationKey2020';
      const encodedPublicKey = 'encoded public key';
      const encodedPrivateKey = 'encoded private key';

      keyPair.addPublicKey = ({key}) => {
        key.publicKeyBase58 = encodedPublicKey;
        return key;
      };
      keyPair.addPrivateKey = ({key}) => {
        key.privateKeyBase58 = encodedPrivateKey;
        return key;
      };
      expect(keyPair.export({publicKey: true, privateKey: true})).to.eql({
        controller: 'did:ex:1234',
        id: 'did:ex:1234#fingerprint',
        publicKeyBase58: 'encoded public key',
        privateKeyBase58: 'encoded private key',
        type: 'ExampleVerificationKey2020'
      });
    });
  });
});
