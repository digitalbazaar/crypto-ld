/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const chai = require('chai');
chai.should();
const {expect} = chai;

const {LDKeyPair} = require('..');

describe('LDKeyPair', () => {
  describe('constructor', () => {
    it('should initialize id and controller', async () => {
      const controller = 'did:ex:1234';
      const id = 'did:ex:1234#fingerprint';
      const keyPair = new LDKeyPair({id, controller});

      expect(keyPair.id).to.equal(id);
      expect(keyPair.controller).to.equal(controller);
    });
  });
});
