const nock = require('nock');
const chai = require('chai');
chai.use(require('dirty-chai'));
chai.should();

const {expect} = chai;

const tls = require('tls');
tls.DEFAULT_ECDH_CURVE = 'auto';

const {VeresOneClient} = require('../lib/index');
const injector = require('./test-injector');

const TEST_HOSTNAME = 'genesis.testnet.veres.one';
const TEST_DID = 'did:v1:test:nym:2pfPix2tcwa7gNoMRxdcHbEyFGqaVBPNntCsDZexVeHX';
const TEST_DID_RESULT = require('./dids/genesis.testnet.did.json');
const LEDGER_AGENTS_DOC = require('./dids/ledger-agents.json');
const ACCELERATOR_RESPONSE = require('./dids/accelerator-response.json');

describe('web ledger client', () => {
  let client;

  beforeEach(() => {
    client = new VeresOneClient({
      injector, mode: 'test', hostname: TEST_HOSTNAME
    });
  });

  describe('veres one client', () => {
    describe('get', () => {
      it('should fetch a did doc from ledger via https', async () => {
        nock('https://genesis.testnet.veres.one')
          .get(`/ledger-agents`)
          .reply(200, LEDGER_AGENTS_DOC);

        nock('https://genesis.testnet.veres.one')
          .post('/ledger-agents/72fdcd6a-5861-4307-ba3d-cbb72509533c' +
               '/query?id=' + TEST_DID)
          .reply(200, TEST_DID_RESULT);

        const result = await client.get({did: TEST_DID});
        expect(result.doc.id).to.equal(TEST_DID);
        expect(result.meta.sequence).to.equal(0);
      });

      it('should fetch just a key object from a did: with hash', async () => {
        nock('https://genesis.testnet.veres.one')
          .get(`/ledger-agents`)
          .reply(200, LEDGER_AGENTS_DOC);

        nock('https://genesis.testnet.veres.one')
          .post('/ledger-agents/72fdcd6a-5861-4307-ba3d-cbb72509533c' +
            '/query?id=' + TEST_DID)
          .reply(200, TEST_DID_RESULT);

        const testKeyId = TEST_DID + '#authn-key-1';

        const expectedDoc = {
          "@context": "https://w3id.org/veres-one/v1",
          "id": "did:v1:test:nym:2pfPix2tcwa7gNoMRxdcHbEyFGqaVBPNntCsDZexVeHX#authn-key-1",
          "type": "Ed25519VerificationKey2018",
          "owner": "did:v1:test:nym:2pfPix2tcwa7gNoMRxdcHbEyFGqaVBPNntCsDZexVeHX",
          "publicKeyBase58": "2pfPix2tcwa7gNoMRxdcHbEyFGqaVBPNntCsDZexVeHX"
        };

        const result = await client.get({did: testKeyId});

        expect(result.doc).to.eql(expectedDoc);
      });
    });

    describe('sendToAccelerator', () => {
      it('should send an operation to an accelerator service', async () => {
        nock('https://genesis.testnet.veres.one')
          .post(`/accelerator/proofs`)
          .reply(200, ACCELERATOR_RESPONSE);

        const operation = {
          "@context": "https://w3id.org/veres-one/v1",
          "type": "CreateWebLedgerRecord",
          "record": {
            "@context": "https://w3id.org/veres-one/v1",
            "id": "did:v1:test:uuid:ad33d59b630f44d49bdfb8266d4a243e"
          }
        };

        const result = await client.sendToAccelerator({
          operation,
          hostname: TEST_HOSTNAME
        });

        const body = result.data;

        expect(body).to.have.property('proof');
      });
    });
  });
});
