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
      sinon.spy(didDoc, 'generateId');

      await didDoc.init({mode});

      expect(didDoc.generateId).to.have.been.called;
    });

    it('should init the authn/authz keys', async () => {
      await didDoc.init(mode);

      expect(didDoc.doc.authentication.length).to.equal(1);
      expect(didDoc.doc.capabilityDelegation.length).to.equal(1);
      expect(didDoc.doc.capabilityInvocation.length).to.equal(1);
    });

    it('should generate an invoke key', async () => {
      await didDoc.init(mode);

      const invokeKey = didDoc.doc.capabilityInvocation[0];
      expect(invokeKey.controller).to.equal(didDoc.id);
      expect(invokeKey.type).to.equal(keyType);
    });
  });

  describe('generateId', () => {
    const keyType = 'Ed25519VerificationKey2018';

    it('should generate a uuid type did', async () => {
      const didType = 'uuid';
      const didDoc = new VeresOneDidDoc({keyType, didType});
      const did = didDoc.generateId({didType, mode: 'test'});

      expect(did).to.match(/^did:v1:test:uuid:.*/);
    });

    it('should generate a nym type did', async () => {
      const didDoc = new VeresOneDidDoc({keyType, didType: 'nym'});
      const keyOptions = {
        type: keyType, passphrase: null
      };

      const keyPair = await LDKeyPair.generate(keyOptions);
      const did = didDoc.generateId({keyPair, mode: 'test'});

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

  describe('exportKeys', () => {
    it('should return an empty object when no keys are present', async () => {
      const didDoc = new VeresOneDidDoc();
      expect(await didDoc.exportKeys()).to.eql({});
    });

    it('should return a hashmap of keys by key id', async () => {
      const didDoc = new VeresOneDidDoc();
      await didDoc.init({mode: 'test', passphrase: null});

      const keys = await didDoc.exportKeys();
      expect(Object.keys(keys).length).to.equal(3);
      for(const k in keys) {
        expect(keys[k]).to.have.property('privateKeyBase58');
      }
    });
  });

  describe('importKeys', () => {
    const exampleDoc = require('./dids/did-v1-test-nym-eddsa-example.json');
    const exampleKeys = require(
      './dids/did-v1-test-nym-eddsa-example-keys.json');
    const keyId = 'did:v1:test:nym:' +
      'z279wbVAtyvuhWzM8CyMScPvS2G7RmkvGrBX5jf3MDmzmow3#authn-1';

    it('should import keys', async () => {
      const didDoc = new VeresOneDidDoc({doc: exampleDoc});

      expect(didDoc.keys).to.eql({}); // no keys

      await didDoc.importKeys(exampleKeys);

      const authKey = didDoc.keys[keyId];
      expect(authKey).to.exist;

      expect(authKey.id).to.equal(keyId);
    });
  });

  describe('addKey/removeKey', () => {
    const exampleDoc = require('./dids/did-v1-test-nym-eddsa-example.json');
    const exampleKeys = require(
      './dids/did-v1-test-nym-eddsa-example-keys.json');
    const did = 'did:v1:test:nym:' +
      'z279wbVAtyvuhWzM8CyMScPvS2G7RmkvGrBX5jf3MDmzmow3';
    const keyId = `${did}#authn-1`;
    const didDoc = new VeresOneDidDoc({doc: exampleDoc});

    it('should add/remove a public key node from the DID Doc', async () => {
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

  describe('service endpoints', () => {
    const exampleDoc = require('./dids/did-v1-test-nym-eddsa-example.json');
    let didDoc;

    beforeEach(() => {
      const doc = JSON.parse(JSON.stringify(exampleDoc)); // clone
      didDoc = new VeresOneDidDoc({doc});
    });

    it('should add a service to the did doc', () => {
      expect(didDoc.hasService({name: 'testAgent'})).to.be.false;
      didDoc.addService({
        name: 'testAgent',
        type: 'AgentService',
        serviceEndpoint: 'https://example.com',
        description: 'test description' // this is a custom property
      });
      expect(didDoc.hasService({name: 'testAgent'})).to.be.true;

      expect(didDoc.findService({name: 'testAgent'}).description)
        .to.equal('test description');
    });

    it('should throw when adding a service that already exists', () => {
      const serviceOptions = {
        name: 'testAgent',
        type: 'AgentService',
        serviceEndpoint: 'https://example.com',
        description: 'test description' // this is a custom property
      };

      didDoc.addService(serviceOptions);

      expect(() => didDoc.addService(serviceOptions))
        .to.throw(/Service with that name or id already exists/);
    });

    it('should remove a service from the did doc', () => {
      didDoc.addService({
        name: 'testService', type: 'Test',
        serviceEndpoint: 'https://example.com'
      });
      expect(didDoc.hasService({name: 'testService'})).to.be.true;

      didDoc.removeService({name: 'testService'});

      expect(didDoc.hasService({name: 'testService'})).to.be.false;
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
