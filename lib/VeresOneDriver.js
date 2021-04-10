/*!
 * Copyright (c) 2018-2021 Veres One Project. All rights reserved.
 */
'use strict';

const didIo = require('@digitalbazaar/did-io');
const {CapabilityInvocation} = require('@digitalbazaar/zcapld');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');
const jsigs = require('jsonld-signatures');
const {Ed25519VerificationKey2020} =
  require('@digitalbazaar/ed25519-verification-key-2020');
const {X25519KeyAgreementKey2020} =
  require('@digitalbazaar/x25519-key-agreement-key-2020');
const uuid = require('uuid-random');

const constants = require('./constants');
const documentLoader = require('./documentLoader');
const veresOneContext = require('veres-one-context');
const VeresOneDidDoc = require('./VeresOneDidDoc');
const VeresOneClient = require('./VeresOneClient');

const {CryptoLD} = require('crypto-ld');
const cryptoLd = new CryptoLD();
cryptoLd.use(Ed25519VerificationKey2020);
cryptoLd.use(X25519KeyAgreementKey2020);

const {DEFAULT_DID_TYPE, DEFAULT_KEY_TYPE, DEFAULT_MODE} = constants;

const DID_DOC_CONTEXTS = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/veres-one/v1',
  'https://w3id.org/security/suites/ed25519-2020/v1',
  'https://w3id.org/security/suites/x25519-2020/v1'
];

const DID_REGEX = /^(did:v1:)(test:)?(uuid|nym):(.+)/;

class VeresOneDriver {
  /**
   * @param [options={}] {object} - Options hashmap
   * @param {string} [options.mode='test'] Ledger mode ('test', 'dev', 'live'),
   *   determines hostname for ledger client.
   * @param {string} [options.hostname] Optional hostname override. If not
   *   provided, ledger hostname will be determined based on `mode`.
   * @param {Agent} [options.httpsAgent] A NodeJS HTTPS Agent (`https.Agent`).
   * @param {object} [options.logger] Optional logger (defaults to console)
   * @param {WebLedgerClient} [options.client]
   */
  constructor({mode, hostname, httpsAgent, logger, client} = {}) {
    // used by did-io to register drivers
    this.method = 'v1';
    this.mode = mode || DEFAULT_MODE;

    this.logger = logger || console;

    this.hostname = hostname ||
      VeresOneDriver.defaultHostname({mode: this.mode});

    this.client = client ||
      new VeresOneClient({
        hostname: this.hostname,
        httpsAgent,
        mode: this.mode,
        logger: this.logger
      });
  }

  /**
   * @returns {string} Hostname for current mode (dev/live etc)
   */
  static defaultHostname({mode} = {}) {
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
  async computeId({
    key, did, didType = DEFAULT_DID_TYPE, mode = this.mode}) {
    if(!did) {
      did = _generateDid({key, didType, mode});
    }
    return _keyId({did, keyPair: key});
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
   * Generates a new DID Document.
   *
   * @param [didType='nym'] {string} DID type, 'nym' or 'uuid'
   * @param [keyType] {string}
   * @param [passphrase] {string}
   * @param [invokeKey] {LDKeyPair} Optional invocation key to serve as the DID
   *   basis (useful if you've generated a key via a KMS).
   * @param [authKey] {LDKeyPair} Optional
   * @param [delegateKey] {LDKeyPair} Optional
   * @param [assertionKey] {LDKeyPair} Optional
   * @param [keyAgreementKey] {LDKeyPair} Optional
   *
   * @returns {Promise<{didDocument: object, keyPairs: Map,
   *   methodFor: Function}>} Resolves with the generated DID Document, along
   *   with the corresponding key pairs used to generate it.
   */
  async generate({
    didType = DEFAULT_DID_TYPE, keyType = DEFAULT_KEY_TYPE,
    invokeKey, authKey, delegateKey, assertionKey,
    keyAgreementKey
  } = {}) {
    const {mode} = this;
    const keyPairs = new Map();

    // Before we initialize the rest of the keys, we need to compose the DID
    // Document `.id` itself, from the capabilityInvocation key pair.
    const capabilityInvocationKeyPair = invokeKey ||
      await cryptoLd.generate({type: keyType});

    // Use the capabilityInvocation key to base the DID URI.
    // This will be either a cryptonym or a uuid type DID.
    const did = _generateDid({key: capabilityInvocationKeyPair, didType, mode});
    if(!capabilityInvocationKeyPair.controller) {
      capabilityInvocationKeyPair.controller = did;
    }
    capabilityInvocationKeyPair.id = _keyId({
      did, keyPair: capabilityInvocationKeyPair
    });
    keyPairs.set(capabilityInvocationKeyPair.id, capabilityInvocationKeyPair);

    // Now that we have a DID, set up the other keys
    const keyOptions = {type: keyType, controller: did};

    // For signing assertions (such as Verifiable Credentials)
    const assertionKeyPair = assertionKey ||
      await cryptoLd.generate(keyOptions);
    assertionKeyPair.id = _keyId({did, keyPair: assertionKeyPair});
    keyPairs.set(assertionKeyPair.id, assertionKeyPair);

    // For signing Verifiable Presentations for DID Auth.
    const authenticationKeyPair = authKey ||
      await cryptoLd.generate(keyOptions);
    authenticationKeyPair.id = _keyId({did, keyPair: authenticationKeyPair});
    keyPairs.set(authenticationKeyPair.id, authenticationKeyPair);

    // For delegating zCaps
    const capabilityDelegationKeyPair = delegateKey ||
      await cryptoLd.generate(keyOptions);
    capabilityDelegationKeyPair.id = _keyId({
      did, keyPair: capabilityDelegationKeyPair
    });
    keyPairs.set(capabilityDelegationKeyPair.id, capabilityDelegationKeyPair);

    // For encryption (for example, using minimal-cipher)
    const keyAgreementKeyPair = keyAgreementKey ||
      await cryptoLd.generate({
        ...keyOptions, type: 'X25519KeyAgreementKey2020'
      });
    keyPairs.set(keyAgreementKeyPair.id, keyAgreementKeyPair);

    const didDocument = {
      '@context': DID_DOC_CONTEXTS,
      id: did,
      authentication: [
        authenticationKeyPair.export({publicKey: true})
      ],
      assertionMethod: [
        assertionKeyPair.export({publicKey: true})
      ],
      capabilityDelegation: [
        capabilityDelegationKeyPair.export({publicKey: true})
      ],
      capabilityInvocation: [
        capabilityInvocationKeyPair.export({publicKey: true})
      ],
      keyAgreement: [
        keyAgreementKeyPair.export({publicKey: true})
      ]
    };

    // Convenience function that returns the public/private key pair instance
    // for a given purpose (authentication, assertionMethod, keyAgreement, etc).
    const methodFor = ({purpose}) => {
      const {id: methodId} = didIo.findVerificationMethod({
        doc: didDocument, purpose
      });
      return keyPairs.get(methodId);
    };

    return {didDocument, keyPairs, methodFor};
  }

  /**
   * Registers a DID Document on the Veres One ledger.
   *
   * @param {object} options - Options hashmap.
   * @param {object} options.didDocument - DID Document to register.
   * @param [options.accelerator] {string} Hostname of accelerator to use
   * @param [options.authDoc] {object} Auth DID Doc, required if using
   *   an accelerator service
   * @returns {Promise<object>} Result of the register operation.
   */
  async register({didDocument, accelerator, authDoc} = {}) {
    // wrap DID Document in a web ledger operation
    const operation = await this.client.wrap(
      {didDocument, operationType: 'create'});
    await this.send(operation, {accelerator, authDoc});

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
      suite: new Ed25519Signature2020({key}),
      purpose: new CapabilityInvocation({capability, capabilityAction})
    });
  }

  /**
   * Adds a zcap delegation proof to a capability DID Document.
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

VeresOneDriver.contexts = {
  [constants.VERES_ONE_CONTEXT_URL]:
    veresOneContext.contexts.get(constants.VERES_ONE_CONTEXT_URL)
};

/**
 * Generates a DID uri, either as a globally unique random string (uuid),
 * or from a given key pair (in case of cryptonym type did).
 *
 * @param {LDKeyPair} [key] - Required for generating a cryptonym DID.
 * @param {string} [didType='nym'] - 'uuid' or 'nym'. If 'nym', a key pair
 *   must also be passed in (to generate the did uri from).
 * @param {string} [mode='dev'] - Client mode (which ledger to connect to).
 *
 * @returns {string} DID uri.
 */
function _generateDid({key, didType = DEFAULT_DID_TYPE, mode = DEFAULT_MODE}) {
  if(didType === 'uuid') {
    const prefix = (mode === 'test') ? 'did:v1:test:' : 'did:v1:';
    return (prefix + 'uuid:' + uuid()).replace(/-/g, '');
  }

  // didType === 'nym'
  if(!key) {
    throw new TypeError('`key` is required to generate cryptonym DID.');
  }

  return _createCryptonymDid({key, mode});
}

function _keyId({did, keyPair}) {
  return keyPair.id || `${did}#${keyPair.fingerprint()}`;
}

/**
 * Creates a cryptonym DID from a given key pair.
 *
 * @param key {LDKeyPair}
 * @param [mode='dev'] {string}
 */
function _createCryptonymDid({key, mode = constants.DEFAULT_MODE}) {
  const prefix = (mode === 'test') ? 'did:v1:test' : 'did:v1';

  return `${prefix}:nym:${key.fingerprint()}`;
}

module.exports = {
  VeresOneDriver,
  DID_REGEX
};
