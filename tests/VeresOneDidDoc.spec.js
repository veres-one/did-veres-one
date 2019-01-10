const sinon = require('sinon');
const chai = require('chai');
chai.use(require('dirty-chai'));
chai.use(require('sinon-chai'));
chai.should();
const {expect} = chai;

const {LDKeyPair} = require('crypto-ld');
const constants = require('../lib/constants');

const injector = require('./test-injector');

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
    const env = 'dev';

    beforeEach(() => {
      didDoc = new VeresOneDidDoc({keyType, injector});
    });

    it('should init the did id', async () => {
      sinon.spy(didDoc, 'generateId');

      await didDoc.init({env});

      expect(didDoc.generateId).to.have.been.called();
    });

    it('should init the authn/authz suites', async () => {
      await didDoc.init(env);

      expect(didDoc.doc.authentication.length).to.equal(1);
      expect(didDoc.doc.capabilityDelegation.length).to.equal(1);
      expect(didDoc.doc.capabilityInvocation.length).to.equal(1);
    });

    it('should generate an invoke key', async () => {
      await didDoc.init(env);

      const invokeKey = didDoc.doc.capabilityInvocation[0];
      expect(invokeKey.controller).to.equal(didDoc.id);
      expect(invokeKey.type).to.equal(keyType);
    });
  });

  describe('generateId', () => {
    const keyType = 'Ed25519VerificationKey2018';

    it('should generate a uuid type did', async () => {
      const didType = 'uuid';
      const didDoc = new VeresOneDidDoc({keyType, didType, injector});
      const did = didDoc.generateId({didType, env: 'dev'});

      expect(did).to.match(/^did:v1:test:uuid:.*/);
    });

    it('should generate a nym type did', async () => {
      const didDoc = new VeresOneDidDoc({keyType, didType: 'nym', injector});
      const keyOptions = {
        type: keyType, injector: didDoc.injector, passphrase: null
      };

      const keyPair = await LDKeyPair.generate(keyOptions);
      const did = didDoc.generateId({keyPair, env: 'dev'});

      expect(did).to.match(/^did:v1:test:nym:.*/);
    });
  });

  describe('validateDid', () => {
    const exampleDoc = require('./dids/did-v1-test-nym-eddsa-example.json');
    let didDoc;

    beforeEach(() => {
      didDoc = new VeresOneDidDoc({});
    });

    it('should throw on invalid/malformed DID', async () => {
      didDoc.doc.id = '1234';
      try {
        await didDoc.validateDid({env: 'test'});
      } catch(error) {
        error.message.should.match(/^Invalid DID format/);
      }

      didDoc.doc.id = 'did:v1:uuid:'; // empty specific id
      try {
        await didDoc.validateDid();
      } catch(error) {
        error.message.should.match(/^Invalid DID format/);
      }

      didDoc.doc.id = 'did:v1:uuid:123%abc'; // invalid character
      try {
        await didDoc.validateDid();
      } catch(error) {
        error.message.should.match(/^Specific id contains invalid characters/);
      }
    });

    it.skip('should throw when test: not present in DID in test mode', () => {
      didDoc.doc.id = 'did:v1:test:uuid:1234';
      (async () => await didDoc.validateDid({env: 'test'}))
        .should.not.throw();

      didDoc.doc.id = 'did:v1:uuid:1234';
      (async () => await didDoc.validateDid({env: 'test'}))
        .should.throw(/^DID is invalid for test mode/);
    });

    it.skip('should throw when test: is present in DID not in test mode', async () => {
      didDoc.doc.id = 'did:v1:uuid:1234';
      (async () => await didDoc.validateDid({env: 'live'})).should.not.throw();

      didDoc.doc.id = 'did:v1:test:uuid:1234';
      (async () => await didDoc.validateDid({env: 'live'}))
        .should.throw(/^Test DID is invalid for/);
    });

    it.skip('should throw if key is not provided for verifying cryptonym', () => {
      didDoc.doc.id = 'did:v1:nym:z1234';
      (async () => didDoc.validateDid())
        .should.throw(/Public key is required for cryptonym verification/);
    });

    it.skip('should validate against the correct invoker key', async () => {
      const didDoc = new VeresOneDidDoc({doc: exampleDoc});
      const invokeKey = didDoc.doc.capabilityInvocation[0].publicKey[0];
      const keyPair = await LDKeyPair.from(invokeKey);
      await didDoc.validateDid({keyPair, env: 'test'});
    });

    it.skip('should throw error if validating against incorrect key', async () => {
      const didDoc = new VeresOneDidDoc({doc: exampleDoc});
      const authKeyPair = await LDKeyPair.from(
        didDoc.doc.authentication[0].publicKey[0]
      );
      try {
        didDoc.validateDid({keyPair: authKeyPair, env: 'test'})
      } catch(error) {
        expect(error.message)
          .to.equal('Invalid DID - fingerprint does not verify against key');
      }
    });
  });

  describe('validateKeyIds', () => {
    let didDoc;

    before(async () => {
      didDoc = new VeresOneDidDoc({injector});
      await didDoc.init({env: 'test', passphrase: null});
    });

    it('should validate key IDs', async () => {
      didDoc.validateKeyIds();
    });

    it('should throw on invalid/malformed key ID', async () => {
      const firstKeyId = Object.keys(didDoc.keys)[0];
      const keyPair = didDoc.keys[firstKeyId];

      keyPair.id = '1234';
      try {
        await didDoc.validateKeyIds();
      } catch(error) {
        error.message.should.match(/^Invalid DID key ID/);
      }

      keyPair.id = `${didDoc.id}#1234`;
      try {
        await didDoc.validateKeyIds();
      } catch(error) {
        error.message.should.match(/^Invalid DID key ID/);
      }

      keyPair.id = `${didDoc.id}#z1234`;
      try {
        await didDoc.validateKeyIds();
      } catch(error) {
        error.message.should.match(/^Invalid DID key ID/);
      }
    });
  });

  describe('exportKeys', () => {
    it('should return an empty object when no keys are present', async () => {
      const didDoc = new VeresOneDidDoc();
      expect(await didDoc.exportKeys()).to.eql({});
    });

    it('should return a hashmap of keys by key id', async () => {
      const didDoc = new VeresOneDidDoc({injector});
      await didDoc.init({env: 'test', passphrase: null});

      const keys = await didDoc.exportKeys();
      expect(Object.keys(keys).length).to.equal(3);
      for(const k in keys) {
        expect(keys[k]).to.have.property('privateKeyBase58');
      }
    });
  });

  describe('importKeys', () => {
    const exampleDoc = require('./dids/did-v1-test-nym-eddsa-example.json');
    const exampleKeys = require('./dids/did-v1-test-nym-eddsa-example-keys.json');
    const keyId = 'did:v1:test:nym:z279wbVAtyvuhWzM8CyMScPvS2G7RmkvGrBX5jf3MDmzmow3#authn-1';

    it('should import keys', async () => {
      const didDoc = new VeresOneDidDoc({doc: exampleDoc, injector});

      expect(didDoc.keys).to.eql({}); // no keys

      await didDoc.importKeys(exampleKeys);

      const authKey = didDoc.keys[keyId];
      expect(authKey).to.exist();

      expect(authKey.id).to.equal(keyId);
    });
  });

  describe('addKey/removeKey', () => {
    const exampleDoc = require('./dids/did-v1-test-nym-eddsa-example.json');
    const exampleKeys = require('./dids/did-v1-test-nym-eddsa-example-keys.json');
    const did = 'did:v1:test:nym:z279wbVAtyvuhWzM8CyMScPvS2G7RmkvGrBX5jf3MDmzmow3';
    const keyId = `${did}#authn-1`;
    const didDoc = new VeresOneDidDoc({doc: exampleDoc, injector});

    it('should add/remove a public key node from the DID Doc', async () => {
      await didDoc.importKeys(exampleKeys);

      const authSuites = didDoc.doc[constants.SUITES.authentication];
      const authKey = authSuites[0];

      didDoc.removeKey(authKey);

      // Check to make sure key is removed
      expect(didDoc.doc[constants.SUITES.authentication]).to.eql([]);
      expect(didDoc.keys[keyId]).to.not.exist();

      // Now re-add the key
      const suiteId = constants.SUITES.authentication;

      const key = await LDKeyPair.from(exampleKeys[keyId]);
      await didDoc.addKey({suiteId, key});

      expect(authSuites).to.eql([key.publicNode({controller: did})]);
      expect(didDoc.keys[keyId]).to.eql(key);
    });
  });

  describe('service endpoints', () => {
    const exampleDoc = require('./dids/did-v1-test-nym-eddsa-example.json');
    let didDoc;

    beforeEach(() => {
      const doc = JSON.parse(JSON.stringify(exampleDoc)); // clone
      didDoc = new VeresOneDidDoc({doc, injector});
    });

    it('should add a service to the did doc', () => {
      expect(didDoc.hasService({name: 'testAgent'})).to.be.false();
      didDoc.addService({
        name: 'testAgent',
        type: 'AgentService',
        serviceEndpoint: 'https://example.com',
        description: 'test description' // this is a custom property
      });
      expect(didDoc.hasService({name: 'testAgent'})).to.be.true();

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
        name: 'testService', type: 'Test', serviceEndpoint: 'https://example.com'
      });
      expect(didDoc.hasService({name: 'testService'})).to.be.true();

      didDoc.removeService({name: 'testService'});

      expect(didDoc.hasService({name: 'testService'})).to.be.false();
    });
  });

  describe('toJSON', () => {
    const keyType = 'Ed25519VerificationKey2018';
    it('should only serialize the document, no other properties', () => {
      const didDoc = new VeresOneDidDoc({keyType, injector});

      expect(JSON.stringify(didDoc))
        .to.equal('{"@context":["https://w3id.org/did/v0.11","https://w3id.org/veres-one/v1"]}');
    });
  });
});
