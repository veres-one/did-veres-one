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

      const invokeKey = didDoc.doc.capabilityInvocation[0].publicKey[0];
      expect(invokeKey.owner).to.equal(didDoc.id);
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

  describe('isCryptonym', () => {
    it('should test for DID type', () => {
      const didDoc = new VeresOneDidDoc({});

      expect(didDoc.isCryptonym()).to.be.false(); // no did yet

      didDoc.id = 'did:v1:nym:z1234';
      expect(didDoc.isCryptonym()).to.be.true();

      didDoc.id = 'did:v1:uuid:1234';
      expect(didDoc.isCryptonym()).to.be.false();
    });
  });

  describe('validateDid', () => {
    const exampleDoc = require('./dids/did-v1-test-nym-eddsa-example.json');
    let didDoc;

    beforeEach(() => {
      didDoc = new VeresOneDidDoc({});
    });

    it('should throw on invalid/malformed DID', () => {
      didDoc.id = '1234';
      (() => didDoc.validateDid({env: 'test'}))
        .should.throw(/^Invalid DID format/);

      didDoc.id = 'did:v1:uuid:'; // empty specific id
      (() => didDoc.validateDid())
        .should.throw(/^Invalid DID format/);

      didDoc.id = 'did:v1:uuid:123%abc'; // invalid character
      (() => didDoc.validateDid())
        .should.throw(/^Specific id contains invalid characters/);
    });

    it('should throw when test: not present in DID in test mode', () => {
      didDoc.id = 'did:v1:test:uuid:1234';
      (() => didDoc.validateDid({env: 'test'}))
        .should.not.throw();

      didDoc.id = 'did:v1:uuid:1234';
      (() => didDoc.validateDid({env: 'test'}))
        .should.throw(/^DID is invalid for test mode/);
    });

    it('should throw when test: is present in DID not in test mode', () => {
      didDoc.id = 'did:v1:uuid:1234';
      (() => didDoc.validateDid({env: 'live'})).should.not.throw();

      didDoc.id = 'did:v1:test:uuid:1234';
      (() => didDoc.validateDid({env: 'live'}))
        .should.throw(/^Test DID is invalid for/);
    });

    it('should throw if key is not provided for verifying cryptonym', () => {
      didDoc.id = 'did:v1:nym:z1234';
      (() => didDoc.validateDid())
        .should.throw(/Public key is required for cryptonym verification/);
    });

    it('should validate against the correct invoker key', async () => {
      const didDoc = new VeresOneDidDoc({doc: exampleDoc});
      const invokeKey = didDoc.doc.capabilityInvocation[0].publicKey[0];
      const keyPair = await LDKeyPair.from(invokeKey);
      await didDoc.validateDid({keyPair, env: 'test'});
    });

    it('should throw error if validating against incorrect key', async () => {
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

  describe('exportKeys', () => {
    it('should return an empty object when no keys are present', async () => {
      const didDoc = new VeresOneDidDoc();
      expect(await didDoc.exportKeys()).to.eql({});
    });

    it('should return a hashmap of keys by key id', async () => {
      const didDoc = new VeresOneDidDoc({injector});
      await didDoc.init({env: 'test', passphrase: null});

      const keys = await didDoc.exportKeys();

      expect(keys[didDoc.id + '#authn-key-1'])
        .to.have.property('privateKeyBase58');
      expect(keys[didDoc.id + '#ocap-invoke-key-1'])
        .to.have.property('privateKeyBase58');
      expect(keys[didDoc.id + '#ocap-delegate-key-1'])
        .to.have.property('privateKeyBase58');
    });
  });

  describe('importKeys', () => {
    const exampleDoc = require('./dids/did-v1-test-nym-eddsa-example.json');
    const exampleKeys = require('./dids/did-v1-test-nym-eddsa-example-keys.json');
    const keyId = 'did:v1:test:nym:z279wbVAtyvuhWzM8CyMScPvS2G7RmkvGrBX5jf3MDmzmow3#authn-key-1';

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
    const keyId = `${did}#authn-key-1`;
    const didDoc = new VeresOneDidDoc({doc: exampleDoc, injector});

    it('should add/remove a public key node from the DID Doc', async () => {
      await didDoc.importKeys(exampleKeys);

      const authSuite = didDoc.doc[constants.SUITES.authentication][0];
      const authKey = authSuite.publicKey[0];

      didDoc.removeKey(authKey);

      // Check to make sure key is removed
      expect(authSuite.publicKey).to.eql([]);
      expect(didDoc.keys[keyId]).to.not.exist();

      // Now re-add the key
      const suiteId = `${did}#auth-suite-1`;

      const key = await LDKeyPair.from(exampleKeys[keyId]);
      await didDoc.addKey({suiteId, key});

      expect(authSuite.publicKey).to.eql([key.publicNode({owner: did})]);
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
        endpoint: 'https://example.com',
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
        endpoint: 'https://example.com',
        description: 'test description' // this is a custom property
      };

      didDoc.addService(serviceOptions);

      expect(() => didDoc.addService(serviceOptions))
        .to.throw(/Service with that name or id already exists/);
    });

    it('should remove a service from the did doc', () => {
      didDoc.addService({
        name: 'testService', type: 'Test', endpoint: 'https://example.com'
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
        .to.equal('{"@context":"https://w3id.org/veres-one/v1"}');
    });
  });
});
