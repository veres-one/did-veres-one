/*!
 * Copyright (c) 2018-2021 Veres One Project. All rights reserved.
 */
'use strict';

const didIo = require('@digitalbazaar/did-io');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');
const {Ed25519VerificationKey2020} =
  require('@digitalbazaar/ed25519-verification-key-2020');
const {X25519KeyAgreementKey2020} =
  require('@digitalbazaar/x25519-key-agreement-key-2020');
const uuid = require('uuid-random');
const constants = require('./constants');
const veresOneContext = require('veres-one-context');
const VeresOneClient = require('./VeresOneClient');

const {CryptoLD} = require('crypto-ld');
const cryptoLd = new CryptoLD();
cryptoLd.use(Ed25519VerificationKey2020);
cryptoLd.use(X25519KeyAgreementKey2020);

const {DEFAULT_DID_TYPE, DEFAULT_KEY_TYPE, DEFAULT_MODE} = constants;

const DID_REGEX = /^(did:v1:)(test:)?(uuid|nym):(.+)/;

const DID_DOC_CONTEXTS = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/veres-one/v1',
  'https://w3id.org/security/suites/ed25519-2020/v1',
  'https://w3id.org/security/suites/x25519-2020/v1'
];

class VeresOneDriver {
  /**
   * @param [options={}] {object} - Options hashmap.
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

    this.hostname = hostname || _defaultHostname({mode: this.mode});

    this.client = client ||
      new VeresOneClient({
        hostname: this.hostname,
        httpsAgent,
        mode: this.mode,
        logger: this.logger
      });
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
   * Generates a new DID Document. (See static `generate()` docstring for
   * details).
   *
   * @returns {Promise<{didDocument: Object, keyPairs: Map,
   *   methodFor: Function}>} Resolves with the generated DID Document, along
   *   with the corresponding key pairs used to generate it.
   */
  async generate({
    didType = DEFAULT_DID_TYPE, keyType = DEFAULT_KEY_TYPE,
    invokeKey, authKey, delegateKey, assertionKey,
    keyAgreementKey
  } = {}) {
    const {mode} = this;
    return VeresOneDriver.generate({
      didType, keyType, mode, invokeKey, authKey, delegateKey, assertionKey,
      keyAgreementKey
    });
  }

  /**
   * Generates a new DID Document.
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {string} [options.didType='nym'] - DID type, 'nym' or 'uuid'.
   * @param {string} [options.keyType=DEFAULT_KEY_TYPE] - Verification key type.
   *
   * The following keys are optional, and will be generated if not passed in.
   *
   * @param {LDKeyPair} [options.invokeKey] - Capability invocation key pair
   *   (useful if you've generated a key via a KMS). If present, used to
   *   deterministically derive a cryptonym DID.
   * @param {LDKeyPair} [options.authKey] - Authentication key pair.
   * @param {LDKeyPair} [options.delegateKey] - Capability delegation key pair.
   * @param {LDKeyPair} [options.assertionKey] - Assertion method key pair.
   * @param {LDKeyPair} [options.keyAgreementKey] - Key agreement key pair.
   *
   * @returns {Promise<{didDocument: object, keyPairs: Map,
   *   methodFor: Function}>} Resolves with the generated DID Document, along
   *   with the corresponding key pairs used to generate it.
   */
  static async generate({
    didType = DEFAULT_DID_TYPE, keyType = DEFAULT_KEY_TYPE, mode,
    invokeKey, authKey, delegateKey, assertionKey,
    keyAgreementKey
  } = {}) {
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
   * Validates the DID of this document.
   * Used by the `veres-one-validator` node.
   *
   * - Ensures DID contains 'test:' when running in 'test' mode and vice versa
   * - If cryptonym DIDs, ensures nym is validated against the invocation key
   * - Tests for invalid characters in the Specific ID
   *
   * @param {object} options - Options hashmap.
   * @param {string} didDocument - DID document to validate.
   * @param {string} [mode='dev'] - Mode: 'test'/'live' etc
   *
   * @returns {Promise<{valid: boolean, error: Error}>} - Resolves with the
   *   validation result.
   */
  static async validateDid({didDocument, mode = constants.DEFAULT_MODE} = {}) {
    if(!(didDocument && didDocument.id)) {
      throw new TypeError('The "didDocument.id" parameter is required.');
    }
    const did = didDocument.id;
    if(typeof did !== 'string') {
      return {
        valid: false,
        error: new Error('DID must be a string.')
      };
    }
    // Make an exception for urn:uuid: type DID (elector pool doc, for example)
    if(did.startsWith('urn:uuid:')) {
      return {valid: true}; // short-circuit, UUID URNs are fine as is
    }

    const match = DID_REGEX.exec(did);

    if(!match) {
      return {
        error: new Error(`Invalid DID format: "${did}".`),
        valid: false
      };
    }

    // [2] undefined or 'test:'
    const didMode = match[2] && match[2].slice(0, -1);
    const type = match[3]; // nym / uuid
    const id = match[4];

    if(mode === 'test' && didMode !== 'test') {
      return {
        error: new Error(`DID is invalid for test mode: "${did}".`),
        valid: false
      };
    }

    if(mode !== 'test' && didMode === 'test') {
      return {
        error: new Error(
          `Test DID does not match mode "${mode}": "${did}".`),
        valid: false
      };
    }

    // ensure no invalid characters
    if((/[^A-Za-z0-9:\-.]+/).exec(id)) {
      return {
        error: new Error(
          `Specific id contains invalid characters: "${did}".`),
        valid: false
      };
    }

    // if type is 'uuid', no further validation necessary at the moment

    if(type === 'nym') {
      return this._validateCryptonymDid({didDocument});
    }

    // success
    return {valid: true};
  }

  /**
   * Validates the (nym-based) DID of this document against invocation key.
   *
   * Note: Only validates the 'nym' part of the DID, assumes the overall
   * format was validated already (by `validateDid()`).
   *
   * @returns {Promise<{valid: boolean, error: Error}>} - Resolves with the
   *   validation result.
   */
  static async _validateCryptonymDid({didDocument} = {}) {
    const did = didDocument.id;
    const capabilityInvocationMethod = didIo.findVerificationMethod({
      doc: didDocument, purpose: 'capabilityInvocation'
    });
    if(!capabilityInvocationMethod) {
      return {
        error: new Error('Cryptonym DID requires a capabilityInvocation key.'),
        valid: false
      };
    }
    const keyPair = await Ed25519Signature2020.from(capabilityInvocationMethod);
    if(!(keyPair && keyPair.publicKeyMultibase)) {
      return {
        error: new Error('Public key is required for cryptonym verification.'),
        valid: false
      };
    }
    const fingerprint = DID_REGEX.exec(did)[4];

    // verifyFingerprint has the desired validator return signature
    return keyPair.verifyFingerprint({fingerprint});
  }

  /**
   * Validates the method IDs of this document. Method IDs must be of the
   * format: did#<multibase fingerprint>
   * Used by `veres-one-validator` nodes.
   *
   * @returns {Promise} validator report
   *   {boolean} valid - true if the DID is valid
   *   {Error} error - included when `valid` is false
   */
  async validateMethodIds() {
    for(const proofPurpose in constants.VERIFICATION_RELATIONSHIPS) {
      const methods = this.getAllVerificationMethods(proofPurpose);
      if(!methods) {
        // This DID document does not contain any methods for this purpose
        continue;
      }
      for(const method of methods) {
        // TODO: support methods that are not LDKeyPairs
        const keyPair = await LDKeyPair.from(method);
        // note: Veres One DID documents presently do not permit keys from
        // other DID documents (or other HTTPS resources, etc)
        const parts = keyPair.id.split('#');
        if(parts.length !== 2) {
          return {
            error: new Error(
              'Invalid DID key ID; key ID must be of the form ' +
              '"<did>#<multibase key fingerprint>".'),
            valid: false
          };
        }

        if(parts[0] !== did) {
          return {
            error: new Error(
              'Invalid DID key ID; key ID does not match the DID.'),
            valid: false
          };
        }

        const fingerprint = parts[1];

        // verifyFingerprint has the same validator return signature
        const result = keyPair.verifyFingerprint(fingerprint);
        if(!result.valid) {
          return result;
        }
      }
    }
    // success
    return {valid: true};
  }
}

VeresOneDriver.contexts = {
  [constants.VERES_ONE_CONTEXT_URL]:
    veresOneContext.contexts.get(constants.VERES_ONE_CONTEXT_URL)
};

/**
 * Creates a DID Document from a cryptonym DID.
 * (This is very similar to how a `did:key` DID document is created.)
 *
 * @param {string} did - Cryptonym DID to re-hydrate into a did document.
 *
 * @returns {Promise<{didDocument: object, keyPairs: Map,
 *   methodFor: Function}>} Resolves with the generated DID Document.
 */
async function fromNym({did} = {}) {
  if(!did) {
    throw new TypeError('The "did" parameter is required.');
  }
  let invokeKey;
  let mode;
  try {
    // Re-hydrate capabilityInvocation public key from fingerprint
    const match = DID_REGEX.exec(did);
    mode = match[2] && match[2].slice(0, -1); // 'test' or otherwise
    const fingerprint = match[4];
    invokeKey = Ed25519Signature2020.fromFingerprint({fingerprint});
  } catch(error) {
    throw new Error(`Invalid cryptonym: ${did}`);
  }
  // Use that key to deterministically construct a DID Doc
  return VeresOneDriver.generate({
    didType: 'nym',
    mode,
    keyType: invokeKey.type,
    invokeKey,
    authKey: invokeKey,
    delegateKey: invokeKey,
    assertionKey: invokeKey
  });
}

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

/**
 * @returns {string} Hostname for current mode (dev/live etc)
 */
function _defaultHostname({mode} = {}) {
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

module.exports = {
  VeresOneDriver,
  fromNym,
  DID_REGEX
};
