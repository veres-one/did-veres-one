/*!
 * Copyright (c) 2018-2023 Veres One Project. All rights reserved.
 */
import * as constants from './constants.js';
import * as didIo from '@digitalbazaar/did-io';
import * as veresOneContext from 'veres-one-context';
import {
  Ed25519VerificationKey2020
} from '@digitalbazaar/ed25519-verification-key-2020';
import {v4 as uuid} from 'uuid';
import {VeresOneClient} from './VeresOneClient.js';
import {
  X25519KeyAgreementKey2020
} from '@digitalbazaar/x25519-key-agreement-key-2020';

import {attachProofs} from './attachProof.js';

import {CryptoLD} from 'crypto-ld';
const DEFAULT_CRYPTO_LD = new CryptoLD();
DEFAULT_CRYPTO_LD.use(Ed25519VerificationKey2020);
DEFAULT_CRYPTO_LD.use(X25519KeyAgreementKey2020);

const {DEFAULT_DID_TYPE, DEFAULT_MODE} = constants;
const DEFAULT_VERIFICATION_SUITE = Ed25519VerificationKey2020;

export const DID_REGEX = /^(did:v1:)(test:)?(uuid|nym):(.+)/;

export const DID_DOC_CONTEXTS = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/veres-one/v1'
];

/**
 * @typedef LDKeyPair
 */
/**
 * @typedef LDKeyPairClass
 */
/**
 * @typedef Agent
 */
/**
 * @typedef WebLedgerClient
 */
/**
 * @typedef CryptoLD
 */

export class VeresOneDriver {
  /**
   * @param {object} [options={}] - Options hashmap.
   * @param {string} [options.mode='test'] - Ledger mode
   *   ('test', 'dev', 'live'), determines hostname for ledger client.
   * @param {string} [options.hostname] - Optional hostname override. If not
   *   provided, ledger hostname will be determined based on `mode`.
   * @param {Agent} [options.httpsAgent] - A NodeJS HTTPS Agent (`https.Agent`).
   * @param {object} [options.logger] - Optional logger (defaults to console).
   * @param {WebLedgerClient} [options.client] - A WebLedgerClient.
   * @param {CryptoLD} [options.cryptoLd] - CryptoLD instance.
   * @param {LDKeyPairClass} [options.verificationSuite] - The verification
   *   suite.
   */
  constructor({
    mode, hostname, httpsAgent, logger, client,
    cryptoLd = DEFAULT_CRYPTO_LD, verificationSuite = DEFAULT_VERIFICATION_SUITE
  } = {}) {
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
    this.cryptoLd = cryptoLd;
    this.verificationSuite = verificationSuite;
  }

  /**
   * Generates and returns the id of a given key. Used by `did-io` drivers.
   *
   * @param {object} options - Options hashmap.
   * @param {LDKeyPair} options.key - The key.
   * @param {string} [options.did] - Optional DID.
   * @param {string} [options.didType] - 'nym' or 'uuid'.
   * @param {string} [options.mode] - 'test', 'dev', 'live' etc.
   *
   * @returns {Promise<string>} Returns the key's id. Async to match the
   *   `did-io` api signature.
   */
  async computeId({
    key, did, didType = DEFAULT_DID_TYPE, mode = this.mode}) {
    if(!did) {
      did = _generateDid({key, didType, mode});
    }
    return _keyId({did, keyPair: key});
  }

  /**
   * Fetches a DID Document for a given DID, or a key document for a given
   * key URL.
   * If a DID is not found on the ledger (and it's a cryptonym), it is
   * constructed from the DID (did:key style) and returned.
   *
   * @param {object} options - Options hashmap.
   * @param {string} [options.did] - URI of a DID, either registered on a
   *   ledger, or unregistered (pairwise cryptonym DID).
   * @param {string} [options.url] - Alias for the `did` param, supported
   *   for better readability of invoking code. Typically used when fetching
   *   a key id.
   *
   * @returns {Promise<object>} Resolves with the fetched or constructed DID
   *   Document.
   */
  async get({did, url} = {}) {
    did = did || url;
    if(!did) {
      throw new TypeError('A "did" or "url" parameter is required.');
    }

    const {didAuthority, hashFragment, didType} = _parseDid({did});
    const isNym = didType === 'nym';

    let didDocument;
    // fetch DID Document from ledger
    try {
      didDocument = await this.client.get({did: didAuthority});
    } catch(e) {
      if(e.name === 'NotFoundError' && isNym) {
        // On a 404 Not Found, construct DID Document from DID, `did:key` style.
        try {
          ({didDocument} = await fromNym({
            did: didAuthority, verificationSuite: this.verificationSuite,
            cryptoLd: this.cryptoLd
          }));
        } catch(e) {
          this.logger.debug(
            `Could not construct initial DID Doc from nym "${didAuthority}" ` +
            `using the ${this.verificationSuite.type} suite.`, {error: e});
          throw e;
        }
      } else {
        throw e;
      }
    }
    if(hashFragment) {
      // This was a key id, return a key document instead of a did document
      return this._getKey({didDocument, methodId: did});
    }

    return didDocument;
  }

  /**
   * Fetches an initial (unregistered) DID Document for a given DID,
   * or a key document for a given key URL. This does not check the ledger,
   * but constructs the DID Document deterministically, did:key style.
   *
   * @param {object} options - Options hashmap.
   * @param {string} [options.did] - URI of a DID, either registered on a
   *   ledger, or unregistered (pairwise cryptonym DID).
   * @param {string} [options.url] - Alias for the `did` param, supported
   *   for better readability of invoking code. Typically used when fetching
   *   a key id.
   *
   * @returns {Promise<object>} Resolves with the constructed DID Document or
   *   public key object.
   */
  async getInitial({did, url} = {}) {
    did = did || url;
    if(!did) {
      throw new TypeError('A "did" or "url" parameter is required.');
    }

    const {didAuthority, hashFragment, didType} = _parseDid({did});
    const isNym = didType === 'nym';

    if(!isNym) {
      throw new TypeError('Only cryptonym DIDs can be used with getInitial().');
    }

    // construct DID Document from DID, `did:key` style.
    const {didDocument} = await fromNym({
      did: didAuthority, verificationSuite: this.verificationSuite,
      cryptoLd: this.cryptoLd
    });
    if(hashFragment) {
      // This was a key id, return a key document instead of a did document
      return this._getKey({didDocument, methodId: did});
    }

    return didDocument;
  }

  async _getKey({didDocument, methodId}) {
    const method = didIo.findVerificationMethod({
      doc: didDocument, methodId
    });
    if(!method) {
      throw new Error(`Verification method "${methodId}" not found ` +
        `in did document "${didDocument.id}".`);
    }
    const keyPair = await this.cryptoLd.from(method);
    return keyPair.export({publicKey: true, includeContext: true});
  }

  /**
   * Generates a new DID Document. (See static `generate()` docstring for
   * details).
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {string} [options.didType='nym'] - DID type, 'nym' or 'uuid'.
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
   * @param {Uint8Array} [options.seed] - A 32-byte array seed for a
   *   deterministic key.
   *
   * @returns {Promise<{didDocument: object, keyPairs: Map,
   *   methodFor: Function}>} Resolves with the generated DID Document, along
   *   with the corresponding key pairs used to generate it.
   */
  async generate({
    didType = DEFAULT_DID_TYPE, invokeKey, authKey, delegateKey, assertionKey,
    keyAgreementKey, seed
  } = {}) {
    const {mode, cryptoLd, verificationSuite} = this;
    return VeresOneDriver.generate({
      didType, cryptoLd, verificationSuite, mode, invokeKey, authKey,
      delegateKey, assertionKey, keyAgreementKey, seed
    });
  }

  /**
   * Generates a new DID Document.
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {string} [options.didType='nym'] - DID type, 'nym' or 'uuid'.
   * @param {CryptoLD} options.cryptoLd - Configured CryptoLD instance.
   * @param {string} options.mode - Ledger mode ('test', 'live', 'dev').
   * @param {LDKeyPairClass} [options.verificationSuite] - Crypto suite to
   *   be used to generate verification keys.
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
   * @param {Uint8Array} [options.seed] - A 32-byte array seed for a
   *   deterministic key.
   *
   * @returns {Promise<{didDocument: object, keyPairs: Map,
   *   methodFor: Function}>} Resolves with the generated DID Document, along
   *   with the corresponding key pairs used to generate it.
   */
  static async generate({
    didType = DEFAULT_DID_TYPE, cryptoLd, mode,
    verificationSuite = DEFAULT_VERIFICATION_SUITE,
    invokeKey, authKey, delegateKey, assertionKey, keyAgreementKey, seed
  } = {}) {
    const cryptoSuiteContexts = new Set();
    const keyPairs = new Map();
    const keyType = verificationSuite.suite;

    // Before we initialize the rest of the keys, we need to compose the DID
    // Document `.id` itself, from the capabilityInvocation key pair.
    const capabilityInvocationKeyPair = invokeKey ||
      await cryptoLd.generate({type: keyType, seed});
    cryptoSuiteContexts
      .add(capabilityInvocationKeyPair.constructor.SUITE_CONTEXT);

    // Use the capabilityInvocation key to base the DID URI.
    // This will be either a cryptonym or a uuid type DID.
    const did = _generateDid({key: capabilityInvocationKeyPair, didType, mode});
    if(!capabilityInvocationKeyPair.controller) {
      capabilityInvocationKeyPair.controller = did;
    }
    const keyId = _keyId({did, keyPair: capabilityInvocationKeyPair});
    capabilityInvocationKeyPair.id = keyId;
    keyPairs.set(capabilityInvocationKeyPair.id, capabilityInvocationKeyPair);

    // Now that we have a DID, set up the other keys

    // For signing assertions (such as Verifiable Credentials)
    const assertionKeyPair = assertionKey || capabilityInvocationKeyPair;
    cryptoSuiteContexts.add(assertionKeyPair.constructor.SUITE_CONTEXT);
    keyPairs.set(assertionKeyPair.id, assertionKeyPair);

    // For signing Verifiable Presentations for DID Auth.
    const authenticationKeyPair = authKey || capabilityInvocationKeyPair;
    cryptoSuiteContexts.add(authenticationKeyPair.constructor.SUITE_CONTEXT);
    keyPairs.set(authenticationKeyPair.id, authenticationKeyPair);

    // For delegating zCaps
    const capabilityDelegationKeyPair = delegateKey ||
      capabilityInvocationKeyPair;
    cryptoSuiteContexts
      .add(capabilityDelegationKeyPair.constructor.SUITE_CONTEXT);
    keyPairs.set(capabilityDelegationKeyPair.id, capabilityDelegationKeyPair);

    // For encryption (for example, using minimal-cipher)
    const keyAgreementKeyPair = keyAgreementKey ||
      _deriveKeyAgreementKey({
        verificationKeyPair: capabilityInvocationKeyPair
      });
    cryptoSuiteContexts.add(keyAgreementKeyPair.constructor.SUITE_CONTEXT);
    keyPairs.set(keyAgreementKeyPair.id, keyAgreementKeyPair);

    const didDocument = {
      '@context': [
        ...DID_DOC_CONTEXTS,
        ...cryptoSuiteContexts
      ],
      id: did,
      capabilityInvocation: [
        capabilityInvocationKeyPair.export({publicKey: true})
      ],
    };

    if(authenticationKeyPair.id === capabilityInvocationKeyPair.id) {
      didDocument.authentication = [authenticationKeyPair.id];
    } else {
      didDocument.authentication = [
        authenticationKeyPair.export({publicKey: true})
      ];
    }
    if(assertionKeyPair.id === capabilityInvocationKeyPair.id) {
      didDocument.assertionMethod = [assertionKeyPair.id];
    } else {
      didDocument.assertionMethod = [
        assertionKeyPair.export({publicKey: true})
      ];
    }
    if(capabilityDelegationKeyPair.id === capabilityInvocationKeyPair.id) {
      didDocument.capabilityDelegation = [capabilityDelegationKeyPair.id];
    } else {
      didDocument.capabilityDelegation = [
        capabilityDelegationKeyPair.export({publicKey: true})
      ];
    }
    didDocument.keyAgreement = [
      keyAgreementKeyPair.export({publicKey: true})
    ];

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
   * @param {Map} options.keyPairs - Map of public/private key pairs involved
   *   in the DID Document (esp the capabilityInvocation keys), stored by
   *   key id.
   * @param {string} [options.accelerator] - Hostname of accelerator to use.
   * @param {object} [options.authDoc] - Auth DID Doc, required if using
   *   an accelerator service.
   *
   * @returns {Promise<object>} Resolves with the registered did document.
   */
  async register({
    didDocument, keyPairs, accelerator, authDoc, ...sendOptions
  } = {}) {
    // wrap DID Document in a web ledger operation
    const operation = await this.client.wrap(
      {didDocument, operationType: 'create'});
    await this.send(
      operation, {accelerator, didDocument, keyPairs, authDoc, ...sendOptions});

    return didDocument;
  }

  /**
   * Records an update to a DID Document on the Veres One ledger.
   *
   * @param {object} options - Options hashmap.
   * @param {object} options.didDocument - DID Document to register.
   * @param {Map} options.keyPairs - Map of public/private key pairs involved
   *   in the DID Document (esp the capabilityInvocation keys), stored by
   *   key id.
   * @param {string} [options.accelerator] - Hostname of accelerator to use.
   * @param {object} [options.authDoc] - Auth DID Doc, required if using
   *   an accelerator service.
   *
   * @returns {Promise<object>} Resolves with the updated did document.
   */
  async update({
    didDocument, keyPairs, accelerator, authDoc
  } = {}) {
    // wrap DID Document in a web ledger operation
    const operation = await this.client.wrap(
      {didDocument, operationType: 'update'});
    await this.send(operation, {accelerator, didDocument, keyPairs, authDoc});

    return didDocument;
  }

  /**
   * Sends a DID Document operation (register/update) the Veres One ledger
   * by:
   *
   *  1. Using an Accelerator service, in which case an authorization DID
   *     Document is required beforehand (typically obtained in exchange for
   *     payment).
   *  2. Ticket service.
   *
   * @param {object} operation - WebLedger operation.
   * @param {string} operation.type - Operation type 'create', 'update' etc.
   *
   * @param {object} options - Options hashmap.
   * @param {object} options.didDocument - DID Document to send to ledger.
   *
   * A capabilityInvocation signature is required, to send anything to the
   * ledger. This means either a keyPairs map (containing public/private key
   * pair instances) OR a signer-type object (from a KMS).
   * @param {Map} [options.keyPairs] - Map of public/private key pairs involved
   *   in the DID Document (esp the capabilityInvocation keys), stored by
   *   key id.
   * @param {{sign: Function, id: string}} [options.signer] - A signer type
   *   object (from a KMS), for the capabilityInvocation key.
   *
   * Needed for Accelerator only (not currently used?).
   * @param {string}  [options.accelerator] - Hostname of accelerator to use.
   * @param {object} [options.authDoc] - Auth DID Doc, required if using
   *   an accelerator service.
   *
   * @returns {Promise<object>} Resolves with the didDocument that was the
   *   result of the operation.
   */
  async send(operation, {
    accelerator, didDocument, keyPairs, signer, authDoc
  } = {}) {
    this.logger.log('Sending to ledger, operation type:', operation.type);

    let capabilityInvocationKeyPair;
    // If keyPairs is not passed in, the `signer` param is used.
    if(keyPairs) {
      const {id: invokeKeyId} = didIo.findVerificationMethod({
        doc: didDocument,
        purpose: 'capabilityInvocation'
      });
      capabilityInvocationKeyPair = keyPairs.get(invokeKeyId);
    }

    // the authentication key is only needed when using Accelerators
    let authenticationKeyPair;
    if(accelerator && keyPairs) {
      const {id: authKeyId} = didIo.findVerificationMethod({
        doc: didDocument,
        purpose: 'authentication'
      });
      authenticationKeyPair = keyPairs.get(authKeyId);
    }

    operation = await attachProofs(
      operation,
      {
        did: didDocument.id, client: this.client,
        capabilityInvocationKeyPair, signer, authenticationKeyPair,
        accelerator, authDoc, mode: this.mode, logger: this.logger
      }
    );

    const response = await this.client.send({operation});

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
   * - Ensures DID contains 'test:' when running in 'test' mode and vice versa.
   * - If cryptonym DIDs, ensures nym is validated against the invocation key.
   * - Tests for invalid characters in the Specific ID.
   *
   * @param {object} options - Options hashmap.
   * @param {string} options.didDocument - DID document to validate.
   * @param {string} [options.mode='dev'] - Mode: 'test'/'live' etc.
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

    let parsedDid;
    try {
      parsedDid = _parseDid({did});
    } catch(e) {
      const error = new Error(`Invalid DID format: "${did}".`);
      error.cause = e;
      return {
        error,
        valid: false
      };
    }

    const {mode: didMode, didType, id} = parsedDid;

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

    if(didType === 'nym') {
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
   * @param {object} options - Options hashmap.
   * @param {string} options.didDocument - A DID document.
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
    const keyPair =
      await Ed25519VerificationKey2020.from(capabilityInvocationMethod);
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
   * @typedef {object} ValidatorReport
   * @property {boolean} [valid] - True if the DID is valid.
   * @property {Error} error - Included when `valid` is false.
   */
  /**
   * Validates the method IDs of this document. Method IDs must be of the
   * format: did#<multibase fingerprint>
   * Used by `veres-one-validator` nodes.
   *
   * @param {object} options - Options hashmap.
   * @param {string} options.didDocument - A DID document.
   *
   * @returns {Promise<ValidatorReport>} Validator report.
   */
  async validateMethodIds({didDocument}) {
    const did = didDocument.id;

    // get all expanded verification methods
    const allVerificationMethods = {};
    for(const proofPurpose of constants.VERIFICATION_RELATIONSHIPS) {
      const methods = didDocument[proofPurpose] || [];
      for(const method of methods) {
        if(typeof method === 'object' && method.id !== undefined) {
          allVerificationMethods[method.id] = method;
        }
      }
    }

    // ensure all methods can be constructed into a verifier
    for(const proofPurpose of constants.VERIFICATION_RELATIONSHIPS) {
      const methodsForProofPurpose = didDocument[proofPurpose] || [];
      const methods = [];
      for(const method of methodsForProofPurpose) {
        if(typeof method === 'object' && method.id !== undefined) {
          methods.push(method);
        } else if(typeof method === 'string') {
          methods.push(allVerificationMethods[method]);
        }
      }
      if(methods.length < 1) {
        // This DID document does not contain any methods for this purpose
        continue;
      }
      for(const method of methods) {
        // TODO: support methods that are not LDKeyPairs
        const keyPair = await this.cryptoLd.from(method);
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
        const result = keyPair.verifyFingerprint({fingerprint});
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
 *
 * This is very similar to how a `did:key` DID document is created.
 *
 * @param {object} options - Options hashmap.
 * @param {string} options.did - Cryptonym DID to re-hydrate into a
 *   did document.
 * @param {CryptoLD} options.cryptoLd - Configured CryptoLD instance.
 * @param {LDKeyPairClass} options.verificationSuite - Crypto suite class to
 *   use to serialize/generate verification keys.
 *
 * @returns {Promise<{didDocument: object, keyPairs: Map,
 *   methodFor: Function}>} Resolves with the generated DID Document.
 */
export async function fromNym({did, cryptoLd, verificationSuite} = {}) {
  if(!did) {
    throw new TypeError('The "did" parameter is required.');
  }
  if(!cryptoLd) {
    throw new TypeError('The "cryptoLd" parameter is required.');
  }
  if(!verificationSuite) {
    throw new TypeError('The "verificationSuite" parameter is required.');
  }
  let invokeKey;
  // Re-hydrate capabilityInvocation public key from fingerprint
  const {didType, id: fingerprint, mode} = _parseDid({did});

  if(didType !== 'nym') {
    throw new Error(`"${did}" is not a cryptonym.`);
  }

  try {
    invokeKey = verificationSuite.fromFingerprint({fingerprint});
    invokeKey.controller = did;
  } catch(error) {
    throw new Error(`Invalid cryptonym: ${did}`);
  }
  // Use that key to deterministically construct a DID Doc
  return VeresOneDriver.generate({
    didType: 'nym',
    mode,
    cryptoLd,
    verificationSuite,
    invokeKey
  });
}

/**
 * Converts an Ed25519 key pair instance to an X25519 key agreement key pair,
 * based on the suite year.
 *
 * @param {LDKeyPair} verificationKeyPair - An Ed25519 verification key pair.
 * @returns {LDKeyPair} Returns the derived key agreement key pair instance.
 */
function _deriveKeyAgreementKey({verificationKeyPair}) {
  let keyAgreementKeyPair;
  if(verificationKeyPair.type === 'Ed25519VerificationKey2020') {
    keyAgreementKeyPair = X25519KeyAgreementKey2020
      .fromEd25519VerificationKey2020({keyPair: verificationKeyPair});
  } else {
    throw new Error(
      'Cannot derive key agreement key from verification key type "' +
      verificationKeyPair.type + '".'
    );
  }
  return keyAgreementKeyPair;
}

function _parseDid({did} = {}) {
  const match = DID_REGEX.exec(did);

  if(!match) {
    throw new Error(`Invalid DID format: "${did}".`);
  }

  // Match [2] is the ledger mode, either undefined (live or dev) or 'test:'
  const mode = match[2] && match[2].slice(0, -1);
  const didType = match[3]; // nym / uuid
  const id = match[4];
  const [didAuthority, hashFragment] = did.split('#');

  return {
    did, mode, didType, id, didAuthority, hashFragment
  };
}

/**
 * Generates a DID uri, either as a globally unique random string (uuid),
 * or from a given key pair (in case of cryptonym type did).
 *
 * @param {object} options - Options hashmap.
 * @param {LDKeyPair} [options.key] - Required for generating a cryptonym DID.
 * @param {string} [options.didType='nym'] - 'uuid' or 'nym'. If 'nym', a key
 *   pair must also be passed in (to generate the did uri from).
 * @param {string} [options.mode='dev'] - Client mode (which ledger to connect
 *   to).
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
  if(keyPair.id && keyPair.id.startsWith('did:v1:')) {
    return keyPair.id;
  }
  return `${did}#${keyPair.fingerprint()}`;
}

/**
 * Creates a cryptonym DID from a given key pair.
 *
 * @param {object} options - Options hashmap.
 * @param {LDKeyPair} options.key - A key pair.
 * @param {string} [options.mode='dev'] - The DID type mode.
 *
 * @returns {string} A cryptonym DID.
 */
function _createCryptonymDid({key, mode = constants.DEFAULT_MODE}) {
  const prefix = (mode === 'test') ? 'did:v1:test' : 'did:v1';

  return `${prefix}:nym:${key.fingerprint()}`;
}

/**
 * @param {object} options - Options hashmap.
 * @param {string} [options.mode] - The DID type mode.
 *
 * @returns {string} Hostname for current mode (dev/live etc).
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
