'use strict';

const chai = require('chai');
const {util: {binary: {base58}}} = require('node-forge');
const multibase = require('multibase');
const multicodec = require('multicodec');
chai.use(require('dirty-chai'));
chai.should();

const {expect} = chai;

const {LDKeyPair, Ed25519KeyPair, RSAKeyPair} = require('../lib/index');

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
        expect(typeof keyPair.fingerprint()).to.equal('string');
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
    });

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
          .to.equal('5hvHHCpocudyac6fT6jJCHe2WThQHsKYsjazkGV2L1Umwj5w9HtzcqoZ886yHJdHKbpC4W2qGhUMPbHNPpNDK6Dj')
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
    });
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
        expect(typeof keyPair.fingerprint()).to.equal('string');
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
