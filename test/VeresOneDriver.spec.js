/*!
 * Copyright (c) 2018-2020 Veres One Project. All rights reserved.
 */
'use strict';

const nock = require('nock');
const chai = require('chai');
chai.should();

const {expect} = chai;

const {Ed25519VerificationKey2020} =
  require('@digitalbazaar/ed25519-verification-key-2020');

const {CryptoLD} = require('crypto-ld');
const {VeresOneDriver} = require('..');

// eslint-disable-next-line max-len
const TEST_DID = 'did:v1:test:nym:z6MkpuEWNixE7JwBfbiZu4feAgtGL8zB1RCAJtKoZNLyJYTJ';
// eslint-disable-next-line max-len
const TEST_SEED = '8c2114a150a16209c653817acc7f3e7e9c6c6290ae93d6689cbd61bb038cd31b';
const UNREGISTERED_NYM =
  'did:v1:test:nym:z6MkiCqJ7vhBXRau9BT9yXA9LxSGarmL4W8gFD8qajBZz4gQ';
const UNREGISTERED_UUID = 'did:v1:test:2G7RmkvGrBX5jf3M';
const UNREGISTERED_DOC = require('./dids/did-nym-unregistered.json');
const TEST_DID_RESULT = require('./dids/ashburn.capybara.did.json');
const LEDGER_AGENTS_DOC = require('./dids/ledger-agents.json');
const LEDGER_AGENT_STATUS = require('./dids/ledger-agent-status.json');
const TICKET_SERVICE_PROOF = require('./dids/ticket-service-proof.json');
const expectedDidDoc = require('./dids/expected-did-doc.json');

describe('methods/veres-one', () => {
  let driver;

  beforeEach(() => {
    driver = new VeresOneDriver({mode: 'test'});
  });

  describe('constructor', () => {
    it('should set mode and method by default', () => {
      driver = new VeresOneDriver();
      expect(driver.mode).to.equal('dev');
      expect(driver.method).to.equal('v1');
    });
  });

  describe.skip('get', () => {
    it('should fetch a DID Doc from a ledger', async () => {
      nock('https://ashburn.capybara.veres.one')
        .get(`/ledger-agents`)
        .reply(200, LEDGER_AGENTS_DOC);
      const {ledgerAgent: [{service: {ledgerQueryService}}]} =
        LEDGER_AGENTS_DOC;
      nock(ledgerQueryService)
        .post('/?id=' + encodeURIComponent(TEST_DID))
        .reply(200, TEST_DID_RESULT);

      _nockLedgerAgentStatus();

      const didDoc = await driver.get({did: TEST_DID});
      expect(didDoc.id).to.equal(TEST_DID);
    });

    it('should derive a DID Doc if it encounters a 404 for nym', async () => {
      nock('https://ashburn.capybara.veres.one')
        .get(`/ledger-agents`)
        .reply(200, LEDGER_AGENTS_DOC);

      const {ledgerAgent: [{service: {ledgerQueryService}}]} =
        LEDGER_AGENTS_DOC;
      nock(ledgerQueryService)
        .post('/?id=' + encodeURIComponent(UNREGISTERED_NYM))
        .reply(404);

      _nockLedgerAgentStatus();

      const result = await driver.get({did: UNREGISTERED_NYM});
      expect(result).to.eql(UNREGISTERED_DOC);
    });

    it('should return a key present in an un-registered DID', async () => {
      nock('https://ashburn.capybara.veres.one')
        .get(`/ledger-agents`)
        .reply(200, LEDGER_AGENTS_DOC);

      const {ledgerAgent: [{service: {ledgerQueryService}}]} =
        LEDGER_AGENTS_DOC;
      nock(ledgerQueryService)
        .post('/?id=' + encodeURIComponent(UNREGISTERED_NYM))
        .reply(404);

      _nockLedgerAgentStatus();

      // eslint-disable-next-line max-len
      const unregisteredKey = 'did:v1:nym:z6MkiCqJ7vhBXRau9BT9yXA9LxSGarmL4W8gFD8qajBZz4gQ#z6MkiCqJ7vhBXRau9BT9yXA9LxSGarmL4W8gFD8qajBZz4gQ';
      const result = await driver.get({did: unregisteredKey});

      expect(result).to.eql({
        '@context': [
          'https://w3id.org/did/v0.11',
          'https://w3id.org/veres-one/v1'
        ],
        // eslint-disable-next-line max-len
        id: 'did:v1:test:nym:z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt#z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt',
        type: 'Ed25519VerificationKey2020',
        // eslint-disable-next-line max-len
        controller: 'did:v1:test:nym:z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt',
        publicKeyBase58: 'QugeAcHQwASabUMTXFNefYdBeD8wU24CENyayNzkXuW'
      });
    });

    it('should throw a 404 getting a non-invoke unregistered key', async () => {
      nock('https://ashburn.capybara.veres.one')
        .get(`/ledger-agents`)
        .reply(200, LEDGER_AGENTS_DOC);

      const {ledgerAgent: [{service: {ledgerQueryService}}]} =
        LEDGER_AGENTS_DOC;
      nock(ledgerQueryService)
        .post('/?id=' + encodeURIComponent(UNREGISTERED_NYM))
        .reply(404);

      _nockLedgerAgentStatus();

      let error;
      let result;
      // eslint-disable-next-line max-len
      const nonInvokeKey = 'did:v1:test:nym:z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt#z6MkrhVjBzL7pjojt3nYxSbNkTkZuCyRh6izYEUJL4pyPbB6';

      try {
        result = await driver.get({did: nonInvokeKey});
      } catch(e) {
        error = e;
      }
      expect(result).not.to.exist;
      expect(error).to.exist;
      error.name.should.equal('NotFoundError');
    });

    it('should throw a 404 if non-nym DID not found on ledger', async () => {
      nock('https://ashburn.capybara.veres.one')
        .get(`/ledger-agents`)
        .reply(200, LEDGER_AGENTS_DOC);

      const {ledgerAgent: [{service: {ledgerQueryService}}]} =
        LEDGER_AGENTS_DOC;
      nock(ledgerQueryService)
        .post('/?id=' + encodeURIComponent(UNREGISTERED_UUID))
        .reply(404);

      _nockLedgerAgentStatus();

      let error;
      let result;
      try {
        result = await driver.get({did: UNREGISTERED_UUID});
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
      driver.mode = 'dev';
      const {didDocument} = await driver.generate();
      expect(didDocument.id).to.match(/^did:v1:nym:z.*/);
    });

    it('should generate a non-test DID in live mode', async () => {
      driver.mode = 'live';
      const {didDocument} = await driver.generate();
      expect(didDocument.id).to.match(/^did:v1:nym:z.*/);
    });

    it('should generate a DID document from seed', async () => {
      const seedBytes = (new TextEncoder()).encode(TEST_SEED).slice(0, 32);
      const {didDocument} = await driver.generate({seed: seedBytes});
      expect(didDocument).to.have.keys([
        '@context', 'id', 'authentication', 'assertionMethod',
        'capabilityDelegation', 'capabilityInvocation', 'keyAgreement'
      ]);
      expect(didDocument.id).to.match(/^did:v1:test:nym:z.*/);
      expect(didDocument['@context']).to.eql([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/veres-one/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1',
        'https://w3id.org/security/suites/x25519-2020/v1'
      ]);
      expect(didDocument).eql(expectedDidDoc);
    });

    it('should generate a cryptonym based DID Document', async () => {
      const {didDocument, methodFor, keyPairs} = await driver.generate();

      expect(didDocument).to.have.keys([
        '@context', 'id', 'authentication', 'assertionMethod',
        'capabilityDelegation', 'capabilityInvocation', 'keyAgreement'
      ]);
      expect(didDocument.id).to.match(/^did:v1:test:nym:z.*/);

      expect(didDocument['@context']).to.eql([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/veres-one/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1',
        'https://w3id.org/security/suites/x25519-2020/v1'
      ]);

      for(const purpose of ['capabilityInvocation', 'keyAgreement']) {
        const [publicKey] = didDocument[purpose];
        expect(publicKey).to.have
          .keys('id', 'type', 'controller', 'publicKeyMultibase');
        expect(publicKey.id.startsWith(publicKey.controller)).to.be.true;

        const keyPair = methodFor({didDocument, purpose});
        expect(publicKey.id).to.equal(keyPair.id);
        expect(keyPair).to.have.property('privateKeyMultibase');
      }
      const invokeKeyId = didDocument.capabilityInvocation[0].id;
      expect(didDocument.authentication[0]).to.equal(invokeKeyId);
      expect(didDocument.assertionMethod[0]).to.equal(invokeKeyId);
      expect(didDocument.capabilityDelegation[0]).to.equal(invokeKeyId);

      expect(keyPairs).to.exist;
    });

    it('should generate a cryptonym based DID Document (2020)', async () => {
      const cryptoLd = new CryptoLD();
      cryptoLd.use(Ed25519VerificationKey2020);

      driver = new VeresOneDriver({
        mode: 'test', cryptoLd, verificationSuite: Ed25519VerificationKey2020
      });
      const {didDocument, methodFor, keyPairs} = await driver.generate();

      expect(didDocument).to.have.keys([
        '@context', 'id', 'authentication', 'assertionMethod',
        'capabilityDelegation', 'capabilityInvocation', 'keyAgreement'
      ]);
      expect(didDocument.id).to.match(/^did:v1:test:nym:z.*/);

      expect(didDocument['@context']).to.eql([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/veres-one/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1',
        'https://w3id.org/security/suites/x25519-2020/v1'
      ]);

      for(const purpose of ['capabilityInvocation', 'keyAgreement']) {
        const [publicKey] = didDocument[purpose];
        expect(publicKey).to.have
          .keys('id', 'type', 'controller', 'publicKeyMultibase');
        expect(publicKey.id.startsWith(publicKey.controller)).to.be.true;

        const keyPair = methodFor({didDocument, purpose});
        expect(publicKey.id).to.equal(keyPair.id);
        expect(keyPair).to.have.property('publicKeyMultibase');
      }
      const invokeKeyId = didDocument.capabilityInvocation[0].id;
      expect(didDocument.authentication[0]).to.equal(invokeKeyId);
      expect(didDocument.assertionMethod[0]).to.equal(invokeKeyId);
      expect(didDocument.capabilityDelegation[0]).to.equal(invokeKeyId);

      expect(keyPairs).to.exist;
    });

    it('should generate uuid-based DID Document in test mode', async () => {
      const {didDocument} = await driver.generate({didType: 'uuid'});
      expect(didDocument.id).to.match(/^did:v1:test:uuid:.*/);
    });

    it('should generate uuid-based DID Document in live mode', async () => {
      driver = new VeresOneDriver({mode: 'live'});
      const {didDocument} = await driver.generate({didType: 'uuid'});
      expect(didDocument.id).to.match(/^did:v1:uuid:.*/);
    });
  });

  describe('computeId', () => {
    let key;

    beforeEach(() => {
      key = {
        fingerprint: () => '12345'
      };
    });

    it('should generate a key id based on a did', async () => {
      key.id = await driver.computeId({did: 'did:v1:test:uuid:abcdef', key});

      expect(key.id).to.equal('did:v1:test:uuid:abcdef#12345');
    });

    it('should generate a cryptonym key id based on fingerprint', async () => {
      key.id = await driver.computeId({key, didType: 'nym', mode: 'live'});

      expect(key.id).to.equal('did:v1:nym:12345#12345');
    });
  });

  describe.skip('register', () => {
    it('should send a doc to ledger for registration', async () => {
      // nock('https://ashburn.capybara.veres.one')
      //   .get(`/ledger-agents`)
      //   .reply(200, LEDGER_AGENTS_DOC);
      //
      // _nockLedgerAgentStatus();
      // _nockTicketService();
      // _nockOperationService();

      const {didDocument} = await driver.generate();
      let error;
      let result;
      try {
        result = await driver.register({didDocument});
      } catch(e) {
        console.error(e);
        console.log(e.details.error.data);
        error = e;
      }
      expect(error).not.to.exist;
      expect(result).to.exist;
    });
  });

  describe('validateDid', () => {
    // const exampleDoc = require('./dids/did-v1-test-nym-eddsa-example.json');
    let didDocument;

    beforeEach(() => {
      didDocument = {};
    });

    it('should throw on invalid/malformed DID', async () => {
      didDocument.id = '1234';
      let result = await VeresOneDriver
        .validateDid({didDocument, mode: 'test'});
      result.should.be.an('object');
      expect(result.valid).to.exist;
      result.valid.should.be.a('boolean');
      result.valid.should.be.false;
      expect(result.error).to.exist;
      result.error.message.should.match(/^Invalid DID format/);

      didDocument.id = 'did:v1:uuid:'; // empty specific id
      result = await VeresOneDriver.validateDid({didDocument});
      result.valid.should.be.false;
      result.error.message.should.match(/^Invalid DID format/);

      didDocument.id = 'did:v1:uuid:123%abc'; // invalid character
      result = await VeresOneDriver.validateDid({didDocument});
      result.valid.should.be.false;
      result.error.message.should.match(
        /^Specific id contains invalid characters/);
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

// eslint-disable-next-line no-unused-vars
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

// eslint-disable-next-line no-unused-vars
function _nockOperationService() {
  const {ledgerAgent: [{service: {ledgerOperationService}}]} =
    LEDGER_AGENTS_DOC;
  nock(ledgerOperationService)
    .post('/')
    .reply(200, (uri, requestBody) => {
      return requestBody.record;
    });
}
