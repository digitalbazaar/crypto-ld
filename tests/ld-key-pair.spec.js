'use strict';

const chai = require('chai');
const {
  md: {sha256},
  pki: {getPublicKeyFingerprint, publicKeyFromPem},
  util: {binary: {base58}}
} = require('node-forge');
const multibase = require('multibase');
const multicodec = require('multicodec');
const multihashes = require('multihashes');
const should = chai.should();

const {expect} = chai;

const {LDKeyPair, Ed25519KeyPair, RSAKeyPair} = require('..');

describe('LDKeyPair', () => {
  describe('Ed25519KeyPair', () => {
    const type = 'Ed25519VerificationKey2018';

    describe('export', () => {
      it('should export id, type and key material', async () => {
        const keyPair = await LDKeyPair.generate({type});
        keyPair.id = '#test-id';
        const exported = await keyPair.export();

        expect(exported.id).to.equal('#test-id');
        expect(exported.type).to.equal(type);
        expect(exported).to.have.property('publicKeyBase58');
        expect(exported).to.have.property('privateKeyBase58');
      });
    });

    describe('fingerprint', () => {
      it('should create an Ed25519 key fingerprint', async () => {
        const keyPair = await Ed25519KeyPair.generate();
        const fingerprint = keyPair.fingerprint();
        fingerprint.should.be.a('string');
        fingerprint.startsWith('z').should.be.true;
      });
      it('should be properly multicodec encoded', async () => {
        const keyPair = await Ed25519KeyPair.generate();
        const fingerprint = keyPair.fingerprint();
        const mcPubkeyBytes = multibase.decode(fingerprint);
        const mcType = multicodec.getCodec(mcPubkeyBytes);
        mcType.should.equal('ed25519-pub');
        const pubkeyBytes = multicodec.rmPrefix(mcPubkeyBytes);
        const encodedPubkey = base58.encode(pubkeyBytes);
        encodedPubkey.should.equal(keyPair.publicKeyBase58);
        expect(typeof keyPair.fingerprint()).to.equal('string');
      });
      it('throws TypeError on improper public key material', async () => {
        const keyPair = await Ed25519KeyPair.generate();
        let error;
        let result;
        keyPair.publicKeyBase58 = 'PUBLICKEYINFO';
        try {
          result = keyPair.fingerprint();
        } catch(e) {
          error = e;
        }
        should.not.exist(result);
        should.exist(error);
        error.should.be.instanceof(TypeError);
        error.message.should.contain('must be Base58 encoded');
      });
    });

    describe('verify fingerprint', () => {
      it('should verify a valid fingerprint', async () => {
        const keyPair = await Ed25519KeyPair.generate();
        const fingerprint = keyPair.fingerprint();
        const result = keyPair.verifyFingerprint(fingerprint);
        expect(result).to.exist;
        result.should.be.an('object');
        expect(result.valid).to.exist;
        result.valid.should.be.a('boolean');
        result.valid.should.be.true;
      });
      it('should reject an improperly encoded fingerprint', async () => {
        const keyPair = await Ed25519KeyPair.generate();
        const fingerprint = keyPair.fingerprint();
        const result = keyPair.verifyFingerprint(fingerprint.slice(1));
        expect(result).to.exist;
        result.should.be.an('object');
        expect(result.valid).to.exist;
        result.valid.should.be.a('boolean');
        result.valid.should.be.false;
        expect(result.error).to.exist;
        result.error.message.should.equal(
          '`fingerprint` must be a multibase encoded string.');
      });
      it('should reject an invalid fingerprint', async () => {
        const keyPair = await Ed25519KeyPair.generate();
        const fingerprint = keyPair.fingerprint();
        // reverse the valid fingerprint
        const t = fingerprint.slice(1).split('').reverse().join('');
        const badFingerprint = fingerprint[0] + t;
        const result = keyPair.verifyFingerprint(badFingerprint);
        expect(result).to.exist;
        result.should.be.an('object');
        expect(result.valid).to.exist;
        result.valid.should.be.a('boolean');
        result.valid.should.be.false;
        expect(result.error).to.exist;
        result.error.message.should.equal(
          'The fingerprint does not match the public key.');
      });
      it('should reject a numeric fingerprint', async () => {
        const keyPair = await Ed25519KeyPair.generate();
        const result = keyPair.verifyFingerprint(123);
        expect(result).to.exist;
        result.should.be.an('object');
        expect(result.valid).to.exist;
        result.valid.should.be.a('boolean');
        result.valid.should.be.false;
        expect(result.error).to.exist;
        result.error.message.should.equal(
          '`fingerprint` must be a multibase encoded string.');
      });
      it('should reject an improperly encoded fingerprint', async () => {
        const keyPair = await Ed25519KeyPair.generate();
        const result = keyPair.verifyFingerprint('zPUBLICKEYINFO');
        expect(result).to.exist;
        result.should.be.an('object');
        expect(result.valid).to.exist;
        result.valid.should.be.a('boolean');
        result.valid.should.be.false;
        expect(result.error).to.exist;
        result.error.message.should.contain('must be Base58 encoded');
      });
    });

    /* eslint-disable max-len */
    describe('static from', () => {
      it('should round-trip load exported keys', async () => {
        const keyPair = await LDKeyPair.generate({type});
        keyPair.id = '#test-id';
        const exported = await keyPair.export();
        const imported = await LDKeyPair.from(exported);

        expect(await imported.export()).to.eql(exported);
      });

      it('should load from exported key storage format', async () => {
        const keyData = JSON.parse(`{
          "id": "did:v1:test:nym:z279nCCZVzxreYfLw3EtFLtBMSVVY2pA6uxKengriMCdG3DF#ocap-invoke-key-1",
          "type": "Ed25519VerificationKey2018",
          "owner": "did:v1:test:nym:z279nCCZVzxreYfLw3EtFLtBMSVVY2pA6uxKengriMCdG3DF",
          "publicKeyBase58": "5U6TbzeAqQtSq9N52XPHFrF5cWwDPHk96uJvKshP4jN5",
          "privateKeyBase58": "5hvHHCpocudyac6fT6jJCHe2WThQHsKYsjazkGV2L1Umwj5w9HtzcqoZ886yHJdHKbpC4W2qGhUMPbHNPpNDK6Dj"
        }`);

        const keyPair = await LDKeyPair.from(keyData);
        expect(keyPair.type).to.equal('Ed25519VerificationKey2018');
        expect(keyPair.id)
          .to.equal('did:v1:test:nym:z279nCCZVzxreYfLw3EtFLtBMSVVY2pA6uxKengriMCdG3DF#ocap-invoke-key-1');
        expect(keyPair.owner)
          .to.equal('did:v1:test:nym:z279nCCZVzxreYfLw3EtFLtBMSVVY2pA6uxKengriMCdG3DF');

        expect(keyPair.publicKeyBase58)
          .to.equal('5U6TbzeAqQtSq9N52XPHFrF5cWwDPHk96uJvKshP4jN5');
        expect(keyPair.privateKeyBase58)
          .to.equal('5hvHHCpocudyac6fT6jJCHe2WThQHsKYsjazkGV2L1Umwj5w9HtzcqoZ886yHJdHKbpC4W2qGhUMPbHNPpNDK6Dj');
      });

      it('should load from legacy privateDidDocument format (ed25519)', async () => {
        const keyData = JSON.parse(`{
          "id": "did:v1:test:nym:z279nCCZVzxreYfLw3EtFLtBMSVVY2pA6uxKengriMCdG3DF#ocap-invoke-key-1",
          "type": "Ed25519VerificationKey2018",
          "owner": "did:v1:test:nym:z279nCCZVzxreYfLw3EtFLtBMSVVY2pA6uxKengriMCdG3DF",
          "publicKeyBase58": "5U6TbzeAqQtSq9N52XPHFrF5cWwDPHk96uJvKshP4jN5",
          "privateKey": {
            "privateKeyBase58": "5hvHHCpocudyac6fT6jJCHe2WThQHsKYsjazkGV2L1Umwj5w9HtzcqoZ886yHJdHKbpC4W2qGhUMPbHNPpNDK6Dj"
          }
        }`);

        const keyPair = await LDKeyPair.from(keyData);
        expect(keyPair.type).to.equal('Ed25519VerificationKey2018');
        expect(keyPair.id)
          .to.equal('did:v1:test:nym:z279nCCZVzxreYfLw3EtFLtBMSVVY2pA6uxKengriMCdG3DF#ocap-invoke-key-1');
        expect(keyPair.owner)
          .to.equal('did:v1:test:nym:z279nCCZVzxreYfLw3EtFLtBMSVVY2pA6uxKengriMCdG3DF');

        expect(keyPair.publicKeyBase58)
          .to.equal('5U6TbzeAqQtSq9N52XPHFrF5cWwDPHk96uJvKshP4jN5');
        expect(keyPair.privateKeyBase58)
          .to.equal('5hvHHCpocudyac6fT6jJCHe2WThQHsKYsjazkGV2L1Umwj5w9HtzcqoZ886yHJdHKbpC4W2qGhUMPbHNPpNDK6Dj');
      });
    }); // end static from
    /* eslint-enable max-len */
  });

  describe('RSAKeyPair', () => {
    const type = 'RsaVerificationKey2018';

    describe('export', () => {
      it('should export id, type and key material', async () => {
        const keyPair = await LDKeyPair.generate({type});
        keyPair.id = '#test-id';
        const exported = await keyPair.export();

        expect(exported.id).to.equal('#test-id');
        expect(exported.type).to.equal(type);
        expect(exported).to.have.property('publicKeyPem');
        expect(exported).to.have.property('privateKeyPem');
      });
    });

    describe('fingerprint', () => {
      it('should create an RSA key fingerprint', async () => {
        const keyPair = await RSAKeyPair.generate();
        const fingerprint = keyPair.fingerprint();
        fingerprint.should.be.a('string');
        fingerprint.startsWith('z').should.be.true;
      });
      it('should be properly multicodec encoded', async () => {
        const keyPair = await RSAKeyPair.generate();
        const fingerprint = keyPair.fingerprint();
        const mcPubkeyBytes = multibase.decode(fingerprint);

        // FIXME: multicodec doesn't know about 0x5d encoding yet
        let error;
        let mcType;
        try {
          mcType = multicodec.getCodec(mcPubkeyBytes);
        } catch(e) {
          error = e;
        }
        expect(mcType).to.be.undefined;
        error.message.should.equal('Code `0x5d` not found');

        const multihashBytes = multicodec.rmPrefix(mcPubkeyBytes);
        mcType = multicodec.getCodec(multihashBytes);
        mcType.should.equal('sha2-256');
        // send hash, including prefix to multihashes.decode
        const hashHex = multihashes.decode(multihashBytes)
          .digest.toString('hex');
        // compute the fingerprint directly from the keyPair
        const fingerprintHex = getPublicKeyFingerprint(
          publicKeyFromPem(keyPair.publicKeyPem), {md: sha256.create()})
          .toHex();
        hashHex.should.equal(fingerprintHex);
      });
    });

    describe('verify fingerprint', () => {
      it('should verify a valid fingerprint', async () => {
        const keyPair = await RSAKeyPair.generate();
        const fingerprint = keyPair.fingerprint();
        const result = keyPair.verifyFingerprint(fingerprint);
        expect(result).to.exist;
        result.should.be.an('object');
        expect(result.valid).to.exist;
        result.valid.should.be.a('boolean');
        result.valid.should.be.true;
      });
      it('should reject an improperly encoded fingerprint', async () => {
        const keyPair = await RSAKeyPair.generate();
        const fingerprint = keyPair.fingerprint();
        const result = keyPair.verifyFingerprint(fingerprint.slice(1));
        expect(result).to.exist;
        result.should.be.an('object');
        expect(result.valid).to.exist;
        result.valid.should.be.a('boolean');
        result.valid.should.be.false;
        expect(result.error).to.exist;
        result.error.message.should.equal(
          '`fingerprint` must be a multibase encoded string.');
      });
      it('should reject an invalid fingerprint', async () => {
        const keyPair = await RSAKeyPair.generate();
        const fingerprint = keyPair.fingerprint();
        // reverse the valid fingerprint
        const t = fingerprint.slice(1).split('').reverse().join('');
        const badFingerprint = fingerprint[0] + t;
        const result = keyPair.verifyFingerprint(badFingerprint);
        expect(result).to.exist;
        result.should.be.an('object');
        expect(result.valid).to.exist;
        result.valid.should.be.a('boolean');
        result.valid.should.be.false;
        expect(result.error).to.exist;
        result.error.message.should.equal(
          'The fingerprint does not match the public key.');
      });
      it('should reject a numeric fingerprint', async () => {
        const keyPair = await RSAKeyPair.generate();
        const result = keyPair.verifyFingerprint(123);
        expect(result).to.exist;
        result.should.be.an('object');
        expect(result.valid).to.exist;
        result.valid.should.be.a('boolean');
        result.valid.should.be.false;
        expect(result.error).to.exist;
        result.error.message.should.equal(
          '`fingerprint` must be a multibase encoded string.');
      });
    });

    describe('static from', () => {
      it('should round-trip load exported keys', async () => {
        const keyPair = await LDKeyPair.generate({type});
        keyPair.id = '#test-id';
        const exported = await keyPair.export();
        const imported = await LDKeyPair.from(exported);

        expect(await imported.export()).to.eql(exported);
      });
    });
  });
});
