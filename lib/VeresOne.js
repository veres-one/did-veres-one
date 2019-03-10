/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */

'use strict';
const constants = require('./constants');
const documentLoader = require('./documentLoader');
const VeresOneDidDoc = require('./VeresOneDidDoc');
const storage = require('./storage');
const {LDKeyPair} = require('crypto-ld');
const VeresOneClient = require('./VeresOneClient');
const VeresOneClientError = require('./VeresOneClientError');
const jsonld = require('jsonld');
const jsigs = require('jsonld-signatures');

class VeresOne {
  /**
   * VeresOne contains the over all settings for your
   * Ledger, keystore, and other parts of the block-chain.
   *
   * @param {Object} [options={}] - Options setup the Veres class.
   * @param {Mode} [options.mode='test'] -
   * Ledger mode 'test', 'dev', 'live',
   * determines hostname for ledger client.
   * @param {string} [options.hostname] - Optional hostname override. If not
   *   provided, ledger hostname will be determined based on `mode`.
   * @param {Object} [options.logger] - Optional logger (defaults to console).
   * @param {WebLedgerClient} [options.client] - A WebLedgerClient.
   *
   * Storage defaults to file-based stores, can be substituted to in-memory
   * for testing.
   * @param {Store} [options.keyStore] - Private key store.
   * @param {Store} [options.didStore] - Local DID Doc cache.
   * @param {Store} [options.metaStore] - DID Doc metadata store.
   */
  constructor(options = {}) {
    this.ledger = 'veres';
    this.mode = options.mode || constants.DEFAULT_MODE;

    this.logger = options.logger || console;

    const hostname = options.hostname || VeresOne.defaultHostname(this.mode);
    this.hostname = hostname;
    this.client = options.client ||
      new VeresOneClient({
        hostname, mode: this.mode, logger: this.logger
      });

    this.keyStore = options.keyStore ||
      storage.keyStore({ledger: this.ledger, mode: this.mode});
    this.metaStore = options.metaStore ||
      storage.metaStore({ledger: this.ledger, mode: this.mode});
    this.didStore = options.didStore ||
      storage.didStore({ledger: this.ledger, mode: this.mode});
  }

  /**
   * @param {Mode} mode - One of 3 modes used to determine the host.
   * @returns {string} Hostname for current mode (dev/live etc).
   */
  static defaultHostname(mode) {
    switch(mode) {
      case 'dev':
        return 'genesis.veres.one.localhost:42443';
      case 'test':
        return 'genesis.testnet.veres.one';
      case 'live':
        return 'veres.one';
      default:
        throw new Error(`Unknown mode: "${mode}".`);
    }
  }

  /**
   * Attaches proofs to an operation by either:
   *
   *  1. Using an Accelerator service, in which case an authorization DID
   *     Document is required beforehand (typically obtained in exchange for
   *     payment). Or,
   *  2. Attaching an Equihash proof of work (requires time).
   *
   * @param {Object} options - An object with an operation and options.
   * @param {Object} options.operation - WebLedger operation
   * @param {Object} options.options - Options for the proofs.
   * @param {string} [options.options.accelerator]
   * - Hostname of accelerator to use
   * @param {VeresOneDidDoc} [options.options.authDoc]
   * - Auth DID Doc, required if using
   *   an accelerator service
   * @param {string} [options.options.notes] - Notes logged for the operation.
   *
   * @returns {Promise<Operation>} An operation document with proofs attached.
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

    // get private key
    const invokeKeyNode = didDocument.getVerificationMethod({
      proofPurpose: 'capabilityInvocation'
    });
    const creator = invokeKeyNode.id;
    const invokeKey = didDocument.keys[invokeKeyNode.id];
    if(!invokeKey) {
      throw new Error('Invocation key required to perform a send.');
    }

    const privateKey = await invokeKey.export();

    // attach capability invocation proof
    const capabilityAction =
      operation.type.startsWith('Create') ? 'RegisterDid' : 'UpdateDidDocument';

    operation = await this.attachInvocationProof({
      operation,
      capability: didDocument.id,
      capabilityAction,
      creator,
      key: privateKey,
    });

    return operation;
  }

  /**
   * Fetches a DID Document for a given DID. First checks the ledger, and if
   * not found, also checks local DID storage (for pairwise DIDs).
   *
   * @param {Object} options - Contains a did and an authObserve property.
   * @param {string} options.did - URI of a DID, either
   * registered on a ledger, or unregistered (pairwise cryptonym DID).
   * @param {boolean} [options.autoObserve=false]
   * - Start tracking changes to the DID Doc (to generate a diff patch later).
   * @throws {Error}
   *
   * @returns {Promise<VeresOneDidDoc>} Returns a doc with the did passed in.
   */
  async get({did, autoObserve = false}) {
    let result;

    try {
      // First, try fetching DID Document from ledger
      result = await this.client.get({did});
    } catch(error) {
      if(error.name !== 'NotFoundError') {
        throw error; // Re-throw (a non-404) error
      }
      // DID was not found on ledger, it may be an unregistered/pairwise
      // DID, so check local DID storage
      const localDidDoc = await this.didStore.get(did);
      if(!localDidDoc) {
        throw error; // local DID not found, re-throw the 404
      }
      result = {
        doc: localDidDoc.doc,
        // @todo: Figure out the correct/official way to denote this, possibly
        // open an issue at https://github.com/w3c-ccg/did-resolution/issues/
        meta: Object.assign({}, localDidDoc.meta, {pairwise: true})
      };
    }

    const didDoc = new VeresOneDidDoc(result);
    const keysData = await this.keyStore.get(did);

    if(keysData) {
      didDoc.importKeys(keysData);
    }

    if(autoObserve) {
      didDoc.observe();
    }

    return didDoc;
  }

  async getLocal({did}) {
    const result = await this.didStore.get(did);
    if(result === null) {
      throw new VeresOneClientError(
        'DID was not found in local storage.', 'NotFoundError', {did});
    }
    for(const k in result.keys) {
      result.keys[k] = await LDKeyPair.from(result.keys[k]);
    }
    return new VeresOneDidDoc(result);
  }

  async getRemote({did}) {
    return this.client.get({did});
  }

  /**
   * Generates a new DID Document with relevant keys, saves keys in key store.
   *
   * @param {Object} options - Options for generating a VeresOneDidDoc.
   * @param {DIDType} [options.didType='nym'] - DID type, 'nym' or 'uuid'.
   *
   * @throws {Error}
   *
   * @returns {Promise<VeresOneDidDoc>} An empty VeresOneDidDoc.
   */
  async generate({didType = 'nym', keyType = constants.DEFAULT_KEY_TYPE,
    passphrase = null, mode = this.mode} = {}) {
    const didDoc = await VeresOneDidDoc.generate({didType, keyType, passphrase,
      mode});

    await this.saveKeys(didDoc);
    await this.saveDoc(didDoc);

    return didDoc;
  }

  /**
   * Saves all the keys (public and private) in the key store.
   *
   * @param {VeresOneDidDoc} didDoc - Doc only needs keys and an id.
   *
   * @returns {Promise} Can be awaited.
   */
  async saveKeys(didDoc) {
    return this.keyStore.put(didDoc.id, await didDoc.exportKeys());
  }
  /**
   * Saves a copy of a document to the store.
   *
   * @param {VeresOneDidDoc} didDoc - A document to be saved.
   *
   * @returns {Promise} Can be awaited.
   */
  async saveDoc(didDoc) {
    // FIXME: the document store is doing on Object.freeze() on the inputs
    // cloning here to prevent `didDoc` from being frozen.
    return this.didStore.put(didDoc.id, jsonld.util.clone(didDoc));
  }

  /**
   * Registers a DID Document on the Veres One ledger.
   *
   * @param {Object} options - Options hashmap, see `send()` docstring.
   * @see send
   *
   * @returns {Promise<Object>} Result of the register operation.
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
   * @param {Object} options - Options hashmap, see `send()` docstring.
   *
   * @returns {Promise<Object>} Result of the update operation.
   */
  async update(options) {
    const {didDocument} = options;
    // wrap DID Document in a web ledger operation
    const operation = await this.client.wrap(
      {didDocument, operationType: 'update'});
    await this.send(operation, options);
    await this.saveKeys(didDocument);
    await this.saveDoc(didDocument);
    return didDocument;
  }

  /**
   * Sends a DID Document operation (register/update) the Veres One ledger
   * by either:
   *
   *  1. Using an Accelerator service, in which case an authorization DID
   *     Document is required beforehand (typically obtained in exchange for
   *     payment).
   *  2. Attaching an Equihash proof of work (requires time).
   *
   * @param {Object} operation - WebLedger operation.
   *
   * @param {Object} options - Options for Operation.
   *
   * @param {VeresOneDidDoc} options.didDocument - Document to update.
   *
   * @param {string} [options.accelerator] - Hostname of accelerator to use.
   * @param {VeresOneDidDoc} [options.authDoc] - Auth DID Doc, required if using
   *   an accelerator service.
   *
   * @param {string} [options.notes] - Notes for the operation.
   *
   * @returns {Promise} Can be awaited.
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

    if(options.notes) {
      // save ledger if requested
      this.meta.saveNotes(didDocument, options);
    }
    return response;
  }

  /**
   * Sends a ledger operation to an accelerator.
   * Required when registering a DID Document (and not using an Equihash proof).
   *
   * @param {Object} options - Contains a document for an accelerator.
   *
   * @returns {Promise<Object>} Response from an axios POST request.
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
   * TODO: support `passphrase` for encrypted private key pem or keep decrypt
   * as the responsibility of the caller?
   *
   * FIXME: use ldocap.js.
   *
   * @param {Object} options - Options for a signature proof.
   * @returns {Promise<Object>} The result of the signing.
   */
  attachInvocationProof({capability, capabilityAction, operation, key}) {
    const {CapabilityInvocation} = require('ocapld');

    const {Ed25519Signature2018} = jsigs.suites;
    const {Ed25519KeyPair} = jsigs;
    return jsigs.sign(operation, {
      documentLoader,
      suite: new Ed25519Signature2018({
        compactProof: false,
        key: new Ed25519KeyPair({
          id: key.id,
          privateKeyBase58: key.privateKeyBase58,
          publicKeyBase58: key.publicKeyBase58,
          type: key.type
        })
      }),
      purpose: new CapabilityInvocation({capability, capabilityAction})
    });
  }

  /**
   * Adds an Equihash proof of work to an operation.
   *
   * @param {Object} options - Options for the proof.
   * @param {Object} options.operation - An operation to be signed.
   * @param {Mode} [mode='dev'] - The mode.
   * @param {Object} [paramaters] - Optional paramaters.
   * @param {number} paramaters.n - Used by ledger config.
   * @param {number} paramaters.k - Used by ledger config.
   *
   * @returns {Promise} Can be awaited.
   */
  attachEquihashProof({operation, mode = 'dev', parameters}) {
    let nParam;
    let kParam;
    if(parameters) {
      if(!(typeof parameters.n === 'number' &&
          typeof parameters.k === 'number')) {
        throw new TypeError(
          '`parameters.n` and `parameters.k` must be integers.');
      }
      nParam = parameters.n;
      kParam = parameters.k;
    } else {
      switch(mode) {
        case 'dev':
        case 'test':
          nParam = 64;
          kParam = 3;
          break;
        case 'live':
          // FIXME: determine from ledger config
          nParam = 144;
          kParam = 5;
          break;
        default:
          throw new Error('"mode" must be "dev", "test", or "live".');
      }
    }

    return jsigs.sign(operation, {
      algorithm: 'EquihashProof2018',
      parameters: {
        n: nParam,
        k: kParam
      }
    });
  }

  /**
   * Adds an ocap delegation proof to a capability DID Document.
   *
   * @param {Object} options - Options for the proof.
   * @param {Object} options.didDocument - The document to be signed.
   * @param {string} options.creator - The creator of the document.
   * @param {string} options.privateKeyPem - The private key.
   *
   * TODO: support `passphrase` for encrypted private key pem or keep decrypt
   *   as the responsibility of the caller?
   * FIXME: use ldocap.js.
   */
  attachDelegationProof({didDocument, creator, privateKeyPem}) {
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
  [constants.VERES_ONE_CONTEXT_URL]: require('veres-one-context')
};

module.exports = VeresOne;
