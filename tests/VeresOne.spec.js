/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */
'use strict';

const nock = require('nock');
const chai = require('chai');
chai.should();

const {expect} = chai;

const {VeresOne} = require('..');

const TEST_DID = 'did:v1:test:nym:2pfPix2tcwa7gNoMRxdcHbEyFGqaVBPNntCsDZexVeHX';
const TEST_DID_RESULT = require('./dids/genesis.bee.did.json');
const LEDGER_AGENTS_DOC = require('./dids/ledger-agents.json');
const LEDGER_AGENT_STATUS = require('./dids/ledger-agent-status.json');
const TICKET_SERVICE_PROOF = require('./dids/ticket-service-proof.json');

describe('methods/veres-one', () => {
  let v1;

  beforeEach(() => {
    v1 = new VeresOne({mode: 'test'});
    // v1 = new VeresOne({hostname: 'genesis.veres.one.localhost:42443'});
  });

  describe('get', () => {
    it('should fetch a DID Doc from a ledger', async () => {
      nock('https://genesis.bee.veres.one')
        .get(`/ledger-agents`)
        .reply(200, LEDGER_AGENTS_DOC);
      const {ledgerAgent: [{service: {ledgerQueryService}}]} =
        LEDGER_AGENTS_DOC;
      nock(ledgerQueryService)
        .post('/?id=' + encodeURIComponent(TEST_DID))
        .reply(200, TEST_DID_RESULT);

      _nockLedgerAgentStatus();

      const didDoc = await v1.get({did: TEST_DID});
      expect(didDoc.id).to.equal(TEST_DID);
    });

    it('should throw a 404 if DID not found on ledger', async () => {
      nock('https://genesis.bee.veres.one')
        .get(`/ledger-agents`)
        .reply(200, LEDGER_AGENTS_DOC);

      const {ledgerAgent: [{service: {ledgerQueryService}}]} =
        LEDGER_AGENTS_DOC;
      nock(ledgerQueryService)
        .post('/?id=' + encodeURIComponent(TEST_DID))
        .reply(404);

      let error;
      let result;
      try {
        result = await v1.get({did: TEST_DID});
      } catch(e) {
        error = e;
      }
      expect(result).not.to.exist;
      expect(error).to.exist;
      error.name.should.equal('NotFoundError');
    });
  });

  describe('generate', () => {
    it('should generate a non-test DID in dev mode', async () => {
      v1.mode = 'dev';
      const didDocument = await v1.generate();
      expect(didDocument.id)
        .to.match(/^did:v1:nym:z.*/);
    });

    it('should generate protected RSA nym-based DID Document', async () => {
      const nymOptions = {
        passphrase: 'foobar',
        keyType: 'RsaVerificationKey2018'
      };
      const didDocument = await v1.generate(nymOptions);
      expect(didDocument.id)
        .to.match(/^did:v1:test:nym:z.*/);
      const authPublicKey = didDocument.doc.authentication[0];
      const publicKeyPem = authPublicKey.publicKeyPem;
      expect(publicKeyPem)
        .to.have.string('-----BEGIN PUBLIC KEY-----');

      const keyPair = await didDocument.keys[authPublicKey.id].export();
      // check the corresponding private key
      expect(keyPair.privateKeyPem)
        .to.have.string('-----BEGIN ENCRYPTED PRIVATE KEY-----');
    });

    it('should generate protected EDD nym-based DID Document', async () => {
      const nymOptions = {passphrase: 'foobar'};
      const didDocument = await v1.generate(nymOptions);

      expect(didDocument.id)
        .to.match(/^did:v1:test:nym:z.*/);
      const authPublicKey = didDocument.doc.authentication[0];
      const publicKeyBase58 = authPublicKey.publicKeyBase58;
      expect(publicKeyBase58).to.exist;

      const keys = await didDocument.exportKeys();

      const exportedKey = keys[authPublicKey.id];

      // check the corresponding private key
      expect(exportedKey.privateKeyJwe.unprotected.alg)
        .to.equal('PBES2-A128GCMKW');
    });

    it('should generate unprotected RSA nym-based DID Document', async () => {
      const nymOptions = {
        passphrase: null,
        keyType: 'RsaVerificationKey2018'
      };
      const didDocument = await v1.generate(nymOptions);

      expect(didDocument.id).to.match(/^did:v1:test:nym:.*/);
      const authPublicKey = didDocument.doc.authentication[0];
      expect(authPublicKey.publicKeyPem)
        .to.have.string('-----BEGIN PUBLIC KEY-----');
      const keyPair = await didDocument.keys[authPublicKey.id].export();
      // check the corresponding private key
      expect(keyPair.privateKeyPem)
        .to.match(/^-----BEGIN (:?RSA )?PRIVATE KEY-----/);

    });

    it('should generate unprotected EDD nym-based DID Document', async () => {
      const nymOptions = {passphrase: null};
      const didDocument = await v1.generate(nymOptions);

      expect(didDocument.id).to.match(/^did:v1:test:nym:.*/);
      const authPublicKey = didDocument.doc.authentication[0];
      expect(authPublicKey.publicKeyBase58).to.exist;

      const exportedKey = await didDocument.keys[authPublicKey.id].export();
      expect(exportedKey.privateKeyBase58).to.exist;
    });

    it('should generate uuid-based DID Document', async () => {
      const uuidOptions = {
        didType: 'uuid',
        keyType: 'RsaVerificationKey2018'
      };
      const didDocument = await v1.generate(uuidOptions);

      expect(didDocument.id).to.match(/^did:v1:test:uuid:.*/);
    });

    it('should generate protected ed25519 nym-based DID Doc', async () => {
      const nymOptions = {
        keyType: 'Ed25519VerificationKey2018',
        passphrase: 'foobar'
      };
      const didDocument = await v1.generate(nymOptions);
      const did = didDocument.id;

      expect(did).to.match(/^did:v1:test:nym:z.*/);
      const fingerprint = did.replace('did:v1:test:nym:', '');

      const invokePublicKey = didDocument.doc.capabilityInvocation[0];

      expect(invokePublicKey.id).to.have.string('nym:z');

      const invokeKey = didDocument.keys[invokePublicKey.id];
      const exportedKey = await invokeKey.export();

      expect(exportedKey.privateKeyJwe.ciphertext)
        .to.have.lengthOf.above(128);
      const result = invokeKey.verifyFingerprint(fingerprint);
      expect(result).to.exist;
      result.should.be.an('object');
      expect(result.valid).to.exist;
      result.valid.should.be.a('boolean');
      result.valid.should.be.true;
    });

    it('should generate unprotected ed25519 nym-based DID Doc', async () => {
      const nymOptions = {
        keyType: 'Ed25519VerificationKey2018',
        passphrase: null
      };
      const didDocument = await v1.generate(nymOptions);
      const did = didDocument.id;

      expect(did).to.match(/^did:v1:test:nym:z.*/);
      const fingerprint = did.replace('did:v1:test:nym:', '');

      const invokePublicKey = didDocument.doc.capabilityInvocation[0];
      const invokeKey = didDocument.keys[invokePublicKey.id];

      expect(invokePublicKey.id).to.have.string('nym:z');

      const result = invokeKey.verifyFingerprint(fingerprint);
      expect(result).to.exist;
      result.should.be.an('object');
      expect(result.valid).to.exist;
      result.valid.should.be.a('boolean');
      result.valid.should.be.true;
    });
  });

  describe('register', () => {
    it('should send a doc to ledger for registration', async () => {
      nock('https://genesis.bee.veres.one')
        .get(`/ledger-agents`)
        .reply(200, LEDGER_AGENTS_DOC);

      _nockLedgerAgentStatus();
      _nockTicketService();
      _nockOperationService();

      const didDocument = await v1.generate();
      let error;
      let result;
      try {
        result = await v1.register({didDocument});
      } catch(e) {
        error = e;
      }
      expect(error).not.to.exist;
      expect(result).to.exist;
    });
  });

  describe.skip('attachDelegationProof', () => {
    it('should attach ocap-ld delegation proof to an operation', async () => {
      let didDocument = await v1.generate({
        passphrase: null, keyType: 'RsaVerificationKey2018'
      });

      const delegationPublicKey = didDocument.doc.capabilityDelegation[0];
      const creator = delegationPublicKey.id;
      const {privateKeyPem} = await didDocument.keys[delegationPublicKey.id]
        .export();

      didDocument = await v1.attachDelegationProof({
        didDocument,
        creator,
        privateKeyPem
      });

      const {proof} = didDocument;
      expect(proof).to.exist;
      expect(proof.type).to.equal('RsaSignature2018');
      expect(proof.proofPurpose).to.equal('capabilityDelegation');
      expect(proof.creator).to.equal(creator);
      expect(proof.jws).to.exist;
    });
  });

  describe.skip('attachInvocationProof', () => {
    it('should attach ld-ocap invocation proof to an operation', async () => {
      const didDocument = await v1.generate({
        passphrase: null, keyType: 'RsaVerificationKey2018'
      });

      let operation = v1.client.wrap({didDocument: didDocument.doc});
      const invokePublicKey = didDocument.doc.capabilityInvocation[0];
      const creator = invokePublicKey.id;

      const {privateKeyPem} = await didDocument.keys[invokePublicKey.id]
        .export();

      operation = await v1.attachInvocationProof({
        operation,
        capability: didDocument.id,
        capabilityAction: operation.type,
        creator,
        privateKeyPem
      });

      expect(operation.type).to.equal('CreateWebLedgerRecord');
      expect(operation.record.id).to.match(/^did:v1:test:nym:.*/);
      expect(operation.record.authentication[0].publicKeyPem)
        .to.have.string('-----BEGIN PUBLIC KEY-----');
      expect(operation.proof).to.exist;
      expect(operation.proof.type).to.equal('RsaSignature2018');
      expect(operation.proof.capabilityAction).to.equal(operation.type);
      expect(operation.proof.proofPurpose).to.equal('capabilityInvocation');
      expect(operation.proof.creator).to.equal(creator);
      expect(operation.proof.jws).to.exist;
    });
  });
});

function _nockLedgerAgentStatus() {
  const {ledgerAgent: [{service: {ledgerAgentStatusService}}]} =
    LEDGER_AGENTS_DOC;
  nock(ledgerAgentStatusService)
    .get('/')
    .times(2)
    .reply(200, LEDGER_AGENT_STATUS);
}

function _nockTicketService() {
  const {service: {'urn:veresone:ticket-service': {id: ticketService}}} =
    LEDGER_AGENT_STATUS;
  nock(ticketService)
    .post('/')
    .reply(200, (uri, requestBody) => {
      const reply = JSON.parse(JSON.stringify(requestBody));
      reply.proof = TICKET_SERVICE_PROOF;
      return reply;
    });
}

function _nockOperationService() {
  const {ledgerAgent: [{service: {ledgerOperationService}}]} =
    LEDGER_AGENTS_DOC;
  nock(ledgerOperationService)
    .post('/')
    .reply(200, (uri, requestBody) => {
      return requestBody.record;
    });
}
