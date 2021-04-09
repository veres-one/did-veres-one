/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */
'use strict';

const sinon = require('sinon');
const chai = require('chai');
chai.use(require('sinon-chai'));
chai.should();
const {expect} = chai;

const {LDKeyPair} = require('crypto-ld');
const constants = require('../lib/constants');

const {VeresOneDidDoc} = require('../lib/index');

describe('VeresOneDidDoc', () => {
  describe('constructor', () => {
    it('should init the doc with context', () => {
      const didDoc = new VeresOneDidDoc();

      expect(didDoc.doc).to.have.property('@context');
    });

    it('should init the id from the document', () => {
      const testId = 'did:v1:test:abc';
      const testDidDoc = {id: testId};

      const didDoc = new VeresOneDidDoc({doc: testDidDoc});
      expect(didDoc.id).to.equal(testId);
    });
  });

  describe('init', () => {
    let didDoc;
    const keyType = 'Ed25519VerificationKey2018';
    const mode = 'dev';

    beforeEach(() => {
      didDoc = new VeresOneDidDoc({keyType});
    });

    it('should init the did id', async () => {
      await didDoc.init({mode});

      expect(didDoc.id.startsWith('did:v1'));
    });

    it('should init the authn/authz keys', async () => {
      await didDoc.init(mode);

      expect(didDoc.doc.authentication.length).to.equal(1);
      expect(didDoc.doc.capabilityDelegation.length).to.equal(1);
      expect(didDoc.doc.capabilityInvocation.length).to.equal(1);
      expect(didDoc.doc.assertionMethod.length).to.equal(1);
    });

    it('should generate an invoke key', async () => {
      await didDoc.init(mode);

      const invokeKey = didDoc.doc.capabilityInvocation[0];
      expect(invokeKey.controller).to.equal(didDoc.id);
      expect(invokeKey.type).to.equal(keyType);
    });
  });

  describe('generateDid', () => {
    const keyType = 'Ed25519VerificationKey2018';

    it('should generate a uuid type did', async () => {
      const didType = 'uuid';
      const did = VeresOneDidDoc.generateDid({didType, mode: 'test'});

      expect(did).to.match(/^did:v1:test:uuid:.*/);
    });

    it('should generate a nym type did', async () => {
      const didType = 'nym';
      const keyOptions = {
        type: keyType, passphrase: null
      };

      const key = await LDKeyPair.generate(keyOptions);
      const did = VeresOneDidDoc.generateDid({key, didType, mode: 'test'});

      expect(did).to.match(/^did:v1:test:nym:.*/);
    });
  });

  describe('validateDid', () => {
    const exampleDoc = require('./dids/did-v1-test-nym-eddsa-example.json');
    let didDoc;

    beforeEach(() => {
      didDoc = new VeresOneDidDoc();
    });

    it('should throw on invalid/malformed DID', async () => {
      didDoc.doc.id = '1234';
      let result = await didDoc.validateDid({mode: 'test'});
      result.should.be.an('object');
      expect(result.valid).to.exist;
      result.valid.should.be.a('boolean');
      result.valid.should.be.false;
      expect(result.error).to.exist;
      result.error.message.should.match(/^Invalid DID format/);

      didDoc.doc.id = 'did:v1:uuid:'; // empty specific id
      result = await didDoc.validateDid();
      result.valid.should.be.false;
      result.error.message.should.match(/^Invalid DID format/);

      didDoc.doc.id = 'did:v1:uuid:123%abc'; // invalid character
      result = await didDoc.validateDid();
      result.valid.should.be.false;
      result.error.message.should.match(
        /^Specific id contains invalid characters/);
    });

    it.skip('should throw when test: not present in DID in test mode', () => {
      didDoc.doc.id = 'did:v1:test:uuid:1234';
      (async () => await didDoc.validateDid({mode: 'test'}))
        .should.not.throw();

      didDoc.doc.id = 'did:v1:uuid:1234';
      (async () => await didDoc.validateDid({mode: 'test'}))
        .should.throw(/^DID is invalid for test mode/);
    });

    it.skip(
      'should throw when test: is present in DID not in test mode',
      async () => {
        didDoc.doc.id = 'did:v1:uuid:1234';
        (async () => await didDoc.validateDid({env: 'live'}))
          .should.not.throw();
        didDoc.doc.id = 'did:v1:test:uuid:1234';
        (async () => await didDoc.validateDid({env: 'live'}))
          .should.throw(/^Test DID is invalid for/);
      });

    it.skip(
      'should throw if key is not provided for verifying cryptonym',
      () => {
        didDoc.doc.id = 'did:v1:nym:z1234';
        (async () => didDoc.validateDid())
          .should.throw(/Public key is required for cryptonym verification/);
      });

    it.skip('should validate against the correct invoker key', async () => {
      const didDoc = new VeresOneDidDoc({doc: exampleDoc});
      const invokeKey = didDoc.doc.capabilityInvocation[0].publicKey[0];
      const keyPair = await LDKeyPair.from(invokeKey);
      await didDoc.validateDid({keyPair, mode: 'test'});
    });

    it.skip('throws error if validating against incorrect key', async () => {
      const didDoc = new VeresOneDidDoc({doc: exampleDoc});
      const authKeyPair = await LDKeyPair.from(
        didDoc.doc.authentication[0].publicKey[0]
      );
      try {
        didDoc.validateDid({keyPair: authKeyPair, mode: 'test'});
      } catch(error) {
        expect(error.message)
          .to.equal('Invalid DID - fingerprint does not verify against key');
      }
    });
  });

  describe('validateMethodIds', () => {
    let didDoc;

    before(async () => {
      didDoc = new VeresOneDidDoc();
      await didDoc.init({mode: 'test', passphrase: null});
    });

    it('should validate method IDs', async () => {
      const result = await didDoc.validateMethodIds();
      expect(result).to.exist;
      result.should.be.an('object');
      expect(result.valid).to.exist;
      result.valid.should.be.a('boolean');
      result.valid.should.be.true;
      expect(result.error).not.to.exist;
    });

    it('should reject invalid/malformed method ID', async () => {
      // mutate a methodId
      const keyPair = didDoc.getVerificationMethod(
        {proofPurpose: 'capabilityInvocation'});
      keyPair.id = '1234';
      let result = await didDoc.validateMethodIds();
      result.valid.should.be.false;
      result.error.message.should.match(/^Invalid DID key ID/);

      keyPair.id = `${didDoc.id}#1234`;
      result = await didDoc.validateMethodIds();
      result.valid.should.be.false;
      result.error.message.should.equal(
        '`fingerprint` must be a multibase encoded string.');

      keyPair.id = `${didDoc.id}#z1234`;
      result = await didDoc.validateMethodIds();
      result.valid.should.be.false;
      result.error.message.should.equal(
        'The fingerprint does not match the public key.');
    });
  });

  describe('key operations', () => {
    const exampleDoc = require('./dids/did-v1-test-nym-eddsa-example.json');
    const exampleKeys = require(
      './dids/did-v1-test-nym-eddsa-example-keys.json');
    const did = 'did:v1:test:nym:' +
      'z279wbVAtyvuhWzM8CyMScPvS2G7RmkvGrBX5jf3MDmzmow3';
    const keyId = did + '#authn-1';

    let doc;

    beforeEach(() => {
      doc = JSON.parse(JSON.stringify(exampleDoc));
    });

    describe('exportKeys', () => {
      it('should return an empty object when no keys are present', async () => {
        const didDoc = new VeresOneDidDoc();
        expect(await didDoc.exportKeys()).to.eql({});
      });

      it('should return a hashmap of keys by key id', async () => {
        const didDoc = new VeresOneDidDoc();
        await didDoc.init({mode: 'test', passphrase: null});

        const keys = await didDoc.exportKeys();
        expect(Object.keys(keys).length).to.equal(4);
        for(const k in keys) {
          expect(keys[k]).to.have.property('privateKeyBase58');
        }
      });
    });

    describe('importKeys', () => {
      it('should import keys', async () => {
        const didDoc = new VeresOneDidDoc({doc});

        expect(didDoc.keys).to.eql({}); // no keys

        await didDoc.importKeys(exampleKeys);

        const authKey = didDoc.keys[keyId];
        expect(authKey).to.exist;

        expect(authKey.id).to.equal(keyId);
      });
    });

    describe('addKey/removeKey', () => {
      it('should add/remove a public key node from the DID Doc', async () => {
        const didDoc = new VeresOneDidDoc({doc});
        await didDoc.importKeys(exampleKeys);

        const authKeys = didDoc.doc[constants.PROOF_PURPOSES.authentication];
        const authKey = authKeys[0];

        didDoc.removeKey(authKey);

        // Check to make sure key is removed
        expect(didDoc.doc[constants.PROOF_PURPOSES.authentication]).to.eql([]);
        expect(didDoc.keys[keyId]).to.not.exist;

        // Now re-add the key
        const proofPurpose = constants.PROOF_PURPOSES.authentication;

        const key = await LDKeyPair.from(exampleKeys[keyId]);
        await didDoc.addKey({proofPurpose, key});

        expect(authKeys).to.eql([key.publicNode({controller: did})]);
        expect(didDoc.keys[keyId]).to.eql(key);
      });
    });

    describe('findKey/findVerificationMethod', () => {
      it('should find key and proof purpose for a key id', () => {
        const didDoc = new VeresOneDidDoc({doc});

        const {proofPurpose, key} = didDoc.findKey({id: keyId});
        expect(proofPurpose).to.equal('authentication');
        expect(key.type).to.equal('Ed25519VerificationKey2018');
      });

      it('should return falsy values if that key id is not found', () => {
        const didDoc = new VeresOneDidDoc({doc});
        const {proofPurpose, key} = didDoc.findKey({id: 'invalid key id'});
        expect(proofPurpose).to.be.undefined;
        expect(key).to.be.undefined;
      });
    });

    describe('rotateKey', () => {
      it('should rotate a key - remove old one, add new', async () => {
        const didDoc = new VeresOneDidDoc({doc});

        const newKey = await didDoc.rotateKey({id: keyId});

        expect(newKey).to.have.property('type', 'Ed25519VerificationKey2018');
        expect(newKey).to.have.property('controller', did);
        expect(newKey.id).to.not.equal(keyId);

        const {proofPurpose, key: foundKey} = didDoc.findKey({id: newKey.id});
        expect(proofPurpose).to.equal('authentication');
        expect(foundKey).to.exist;
        expect(foundKey.id).to.equal(newKey.id);
      });

      it('should throw an error if key to be rotated not present', async () => {
        const didDoc = new VeresOneDidDoc({doc});
        let thrownError;

        try {
          await didDoc.rotateKey({id: 'non existent key'});
        } catch(error) {
          thrownError = error;
        }

        expect(thrownError).to.exist;
        expect(thrownError.message).to.match(/is not found in did document/);
      });
    });
  });

  describe('service endpoints', () => {
    const exampleDoc = require('./dids/did-v1-test-nym-eddsa-example.json');
    let didDoc;

    beforeEach(() => {
      const doc = JSON.parse(JSON.stringify(exampleDoc)); // clone
      didDoc = new VeresOneDidDoc({doc});
    });

    it('should add a service to the did doc', () => {
      expect(didDoc.hasService({fragment: 'testAgent'})).to.be.false;
      didDoc.addService({
        endpoint: 'https://example.com',
        fragment: 'testAgent',
        type: 'urn:AgentService',
      });
      expect(didDoc.hasService({fragment: 'testAgent'})).to.be.true;
    });

    it('should throw when adding a service that already exists', () => {
      const serviceOptions = {
        endpoint: 'https://example.com',
        fragment: 'testAgent',
        type: 'urn:AgentService',
      };

      didDoc.addService(serviceOptions);

      expect(() => didDoc.addService(serviceOptions))
        .to.throw(/Service with that name or id already exists/);
    });

    it('should remove a service from the did doc', () => {
      didDoc.addService({
        endpoint: 'https://example.com',
        fragment: 'testService',
        type: 'urn:Test',
      });
      expect(didDoc.hasService({fragment: 'testService'})).to.be.true;

      didDoc.removeService({fragment: 'testService'});

      expect(didDoc.hasService({fragment: 'testService'})).to.be.false;
    });
  });

  describe('toJSON', () => {
    const keyType = 'Ed25519VerificationKey2018';
    it('should only serialize the document, no other properties', () => {
      const didDoc = new VeresOneDidDoc({keyType});

      expect(JSON.stringify(didDoc))
        .to.equal('{"@context":["https://w3id.org/did/v0.11",' +
          '"https://w3id.org/veres-one/v1"]}');
    });
  });
});
