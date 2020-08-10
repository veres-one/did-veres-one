/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const documentLoader = require('./documentLoader');
const veresOneContext = require('veres-one-context');
const VeresOneDidDoc = require('./VeresOneDidDoc');
const VeresOneClient = require('./VeresOneClient');

const jsigs = require('jsonld-signatures');
const {CapabilityInvocation} = require('ocapld');
const {Ed25519Signature2018} = require('@digitalbazaar/ed25519-signature-2018');

class VeresOne {
  /**
   * @param [options={}] {object}
   *
   * @param [options.mode='test'] {string} Ledger mode ('test', 'dev', 'live'),
   *   determines hostname for ledger client.
   * @param [options.hostname] {string} Optional hostname override. If not
   *   provided, ledger hostname will be determined based on `mode`.
   * @param [options.httpsAgent] {Agent} A NodeJS HTTPS Agent (`https.Agent`).
   * @param [options.logger] {object} Optional logger (defaults to console)
   * @param [options.client] {WebLedgerClient}
   */
  constructor(options = {}) {
    this.method = 'v1';
    this.mode = options.mode || constants.DEFAULT_MODE;

    this.logger = options.logger || console;

    const hostname = options.hostname || VeresOne.defaultHostname(this.mode);
    this.hostname = hostname;

    this.client = options.client ||
      new VeresOneClient({
        hostname,
        httpsAgent: options.httpsAgent,
        mode: this.mode,
        logger: this.logger
      });
  }

  /**
   * @returns {string} Hostname for current mode (dev/live etc)
   */
  static defaultHostname(mode) {
    switch(mode) {
      case 'dev':
        return 'node-1.veres.one.local:45443';
      case 'test':
        return 'ashburn.capybara.veres.one';
      case 'live':
        return 'veres.one';
      default:
        throw new Error(`Unknown mode: "${mode}".`);
    }
  }

  /**
   * Attaches proofs to an operation by:
   *
   *  1. Using an Accelerator service, in which case an authorization DID
   *     Document is required beforehand (typically obtained in exchange for
   *     payment).
   *
   * @param operation {object} WebLedger operation
   *
   * @param options {object}
   *
   * @param [options.accelerator] {string} Hostname of accelerator to use
   * @param [options.authDoc] {VeresOneDidDoc} Auth DID Doc, required if using
   *   an accelerator service
   *
   * @param [options.notes]
   *
   * @returns {Promise<Operation>} an operation document with proofs attached.
   */
  async attachProofs({operation, options}) {
    const {didDocument} = options;

    if(options.accelerator) {
      // send operation to an accelerator for proof
      this.logger.log('Sending to accelerator for proof:', options.accelerator);
      operation = await this.attachAcceleratorProof({operation, ...options});
    } else {
      // send to ticket service for a proof
      operation = await this.attachTicketServiceProof({operation});
    }

    // get the capability invocation key, for signing the proof
    const invokeKeyNode = didDocument.getVerificationMethod({
      proofPurpose: 'capabilityInvocation'
    });
    const creator = invokeKeyNode.id;
    const invokeKey = didDocument.keys[invokeKeyNode.id];
    if(!invokeKey || !invokeKey.privateKey) {
      throw new Error('Invocation key required to perform a send.');
    }

    // attach capability invocation proof
    const capabilityAction =
      operation.type.startsWith('Create') ? 'create' : 'update';

    operation = await this.attachInvocationProof({
      operation,
      capability: didDocument.id,
      capabilityAction,
      creator,
      key: invokeKey
    });

    return operation;
  }

  /**
   * Generates and returns the id of a given key. Used by `did-io` drivers.
   *
   * @param {LDKeyPair} key
   * @param {string} [did] - Optional DID.
   * @param {string} [didType] - 'nym' or 'uuid'
   * @param {string} [mode] - 'test', 'dev', 'live' etc.
   *
   * @returns {Promise<string>} Returns the key's id. (Async to match the
   *   `did-io` api signature.)
   */
  async computeKeyId({
    key, did, didType = constants.DEFAULT_DID_TYPE, mode = this.mode}) {
    if(!did) {
      did = VeresOneDidDoc.generateDid({key, didType, mode});
    }
    return VeresOneDidDoc.generateKeyId({did, keyPair: key});
  }

  /**
   * Fetches a DID Document for a given DID. First checks the ledger, and if
   * not found, also checks local DID storage (for pairwise DIDs).
   *
   * @param did {string} URI of a DID, either registered on a ledger, or
   *   unregistered (pairwise cryptonym DID).
   *
   * @param [keys] {object} Hashmap of keys by key id, to import into DID Doc.
   * @param forceConstruct {boolean} Forces deterministic construction of
   *   DID Document from cryptonym.
   * @param [autoObserve=false] {boolean} Start tracking changes to the DID Doc
   *   (to generate a diff patch later).
   *
   * @throws {Error}
   *
   * @returns {Promise<VeresOneDidDoc>}
   */
  async get({did, keys, forceConstruct = false, autoObserve = false}) {
    // fetch DID Document from ledger
    const result = await this.client.get({did, forceConstruct});

    const didDoc = new VeresOneDidDoc(result);

    if(keys) {
      didDoc.importKeys(keys);
    }

    if(autoObserve) {
      didDoc.observe();
    }

    return didDoc;
  }

  /**
   * Generates a new DID Document with relevant keys, saves keys in key store.
   *
   * @param [didType='nym'] {string} DID type, 'nym' or 'uuid'
   * @param [keyType] {string}
   * @param [passphrase] {string}
   * @param [mode] {string} Defaults to the driver's mode
   * @param [invokeKey] {LDKeyPair} Optional invocation key to serve as the DID
   *   basis (useful if you've generated a key via a KMS).
   * @param [authKey] {LDKeyPair} Optional
   * @param [delegateKey] {LDKeyPair} Optional
   * @param [assertionKey] {LDKeyPair} Optional
   *
   * @throws {Error}
   *
   * @returns {Promise<VeresOneDidDoc>}
   */
  async generate({
    didType = constants.DEFAULT_DID_TYPE, keyType = constants.DEFAULT_KEY_TYPE,
    passphrase = null, mode = this.mode, invokeKey, authKey, delegateKey,
    assertionKey
  } = {}) {
    return VeresOneDidDoc.generate({
      didType, keyType, passphrase, mode, invokeKey, authKey, delegateKey,
      assertionKey
    });
  }

  /**
   * Registers a DID Document on the Veres One ledger.
   *
   * @param options {object} Options hashmap, see `send()` docstring.
   *
   * @returns {Promise<object>} Result of the register operation.
   */
  async register(options) {
    const {didDocument} = options;
    // wrap DID Document in a web ledger operation
    const operation = await this.client.wrap(
      {didDocument, operationType: 'create'});
    await this.send(operation, options);

    return didDocument;
  }

  /**
   * Records an update to a DID Document on the Veres One ledger.
   *
   * @param options {object} Options hashmap, see `send()` docstring.
   *
   * @returns {Promise<object>} Result of the update operation.
   */
  async update(options) {
    const {didDocument} = options;
    // wrap DID Document in a web ledger operation
    const operation = await this.client.wrap(
      {didDocument, operationType: 'update'});
    await this.send(operation, options);
    return didDocument;
  }

  /**
   * Sends a DID Document operation (register/update) the Veres One ledger
   * by:
   *
   *  1. Using an Accelerator service, in which case an authorization DID
   *     Document is required beforehand (typically obtained in exchange for
   *     payment).
   *
   * @param operation {object} WebLedger operation
   *
   * @param options {object}
   *
   * @param options.didDocument {VeresOneDidDoc} Document to update
   *
   * @param [options.accelerator] {string} Hostname of accelerator to use
   * @param [options.authDoc] {VeresOneDidDoc} Auth DID Doc, required if using
   *   an accelerator service
   *
   * @param [options.notes]
   *
   * @returns {Promise}
   */
  async send(operation, options) {
    this.logger.log('Sending to ledger, operation type:', operation.type);
    const {didDocument} = options;

    operation = await this.attachProofs({operation, options});

    // get private key
    const invokeKeyNode = didDocument.getVerificationMethod(
      {proofPurpose: 'capabilityInvocation'});

    const authKey = didDocument.keys[invokeKeyNode.id];

    const response = await this.client.send({operation, authKey, ...options});

    if(operation.type === 'create') {
      this.logger.log('DID registration sent to ledger.');
    } else {
      this.logger.log('DID Document update sent to the Veres One ledger.');
    }

    return response;
  }

  /**
   * Sends a ledger operation to an accelerator.
   * Required when registering a DID Document (and not using a proof of work).
   *
   * @param options {object}
   *
   * @returns {Promise<object>} Response from an axios POST request
   */
  async attachAcceleratorProof(options) {
    let authKey;

    try {
      authKey = options.authDoc.getVerificationMethod(
        {proofPurpose: 'authentication'});
    } catch(error) {
      throw new Error('Missing or invalid Authorization DID Doc.');
    }

    // send DID Document to a Veres One accelerator
    this.logger.log('Generating accelerator signature...');
    return this.client.sendToAccelerator({
      operation: options.operation,
      hostname: options.accelerator,
      env: options.mode,
      authKey
    });
  }

  /**
   * Adds an ocap invocation proof to an operation.
   *
   * @param {string} capability - capability url (did)
   * @param {string} capabilityAction - Here, 'create' or 'update'
   * @param {object} operation - WebLedger operation result (either from
   *   `attachAcceleratorProof()` or `attachTicketServiceProof()`)
   * @param {Ed25519KeyPair} key - invocation key
   *
   * @returns {Promise<object>}
   */
  async attachInvocationProof({capability, capabilityAction, operation, key}) {
    return jsigs.sign(operation, {
      documentLoader,
      compactProof: false,
      suite: new Ed25519Signature2018({key}),
      purpose: new CapabilityInvocation({capability, capabilityAction})
    });
  }

  /**
   * Adds an ocap delegation proof to a capability DID Document.
   */
  async attachDelegationProof({didDocument, creator, privateKeyPem}) {
    // FIXME: validate didDocument, creator, and privateKeyPem
    // TODO: support `signer` API as alternative to `privateKeyPem`
    return jsigs.sign(didDocument.doc, {
      algorithm: 'RsaSignature2018',
      creator,
      privateKeyPem,
      proof: {
        '@context': constants.VERES_ONE_CONTEXT_URL,
        proofPurpose: 'capabilityDelegation'
      }
    });
  }

  async attachTicketServiceProof({operation}) {
    const s = await this.client.getStatus();
    const ticketService = s.service['urn:veresone:ticket-service'].id;
    const result = await this.client.getTicketServiceProof(
      {operation, ticketService});
    return result.operation;
  }
}

VeresOne.contexts = {
  [constants.VERES_ONE_CONTEXT_URL]:
    veresOneContext.contexts.get(constants.VERES_ONE_CONTEXT_URL)
};

module.exports = VeresOne;
