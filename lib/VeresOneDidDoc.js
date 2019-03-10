/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const {LDKeyPair} = require('crypto-ld');

const uuid = require('uuid/v4');
const jsonpatch = require('fast-json-patch');
const jsonld = require('jsonld');

const VERES_DID_REGEX = /^(did:v1:)(test:)?(uuid|nym):(.+)/;
const didContexts = [
  constants.DID_CONTEXT_URL,
  constants.VERES_ONE_CONTEXT_URL
];

class VeresOneDidDoc {
  constructor(options = {}) {
    this.doc = options.doc || {'@context': didContexts};
    this.meta = options.meta || {sequence: 0};

    this.observer = null; // JSON Patch change observer

    // Includes private keys -- this property will not be serialized.
    this.keys = options.keys || {};
  }

  /**
   * Generates a new DID Document and initializes various authentication
   * and authorization proof purpose keys.
   *
   * @param {Object} options - Options for the generator.
   * @param {DIDType} [options.didType='nym'] - DID type, 'nym' or 'uuid'.
   * @param {Mode} [options.mode] - 'dev'/'live' etc.
   *
   * Params needed for key generation:
   * @param {string} [options.keyType] - Encryption type of the key.
   * @param {string} [options.passphrase] - Passphrase for the key.
   *
   * @throws {Error}
   *
   * @returns {VeresOneDidDoc} Await a document.
   */
  static async generate(options) {
    const keyType = options.keyType || constants.DEFAULT_KEY_TYPE;
    if(!constants.SUPPORTED_KEY_TYPES.includes(keyType)) {
      throw new Error(`Unknown key type: "${keyType}".`);
    }

    const did = new VeresOneDidDoc(options);
    await did.init({keyType, ...options});
    return did;
  }

  /**
   * Returns the DID uri.
   */
  get id() {
    return this.doc.id;
  }

  /**
   * Initializes an empty (newly created) DID document, by generating an id,
   * as well as authentication and authorization keys.
   * Only called when generating a new DID Doc (creates new keys, etc).
   *
   * @param {Mode} [mode] - The current mode.
   * @param {string} [passphrase] - Passphrase for the key.
   * @param {string} [keyType] - A type of key.
   * @param {DIDType} [didType] - The did's type.
   *
   * @returns {Promise} Can be awaited.
   */
  async init({
    mode, passphrase, didType, keyType = constants.DEFAULT_KEY_TYPE
  }) {
    const keyOptions = {type: keyType, passphrase};

    // Generate a capabilityInvocation key, to base the DID URI on
    const invokeKey = await LDKeyPair.generate(keyOptions);
    const did = this.generateId({keyPair: invokeKey, didType, mode});
    this.doc.id = did;

    // assign the DID as the controller for the keys
    invokeKey.controller = did;
    keyOptions.controller = did;

    // Generate an authentication key pair and proof purpose node
    const authKey = await LDKeyPair.generate(keyOptions);
    authKey.id = this.generateKeyId({did, keyPair: authKey});
    this.doc[constants.PROOF_PURPOSES.authentication] = [authKey.publicNode()];
    this.keys[authKey.id] = authKey;

    // Generate a capabilityDelegation key pair and proof purpose node
    const delegateKey = await LDKeyPair.generate(keyOptions);
    delegateKey.id = this.generateKeyId({did, keyPair: delegateKey});
    this.doc[constants.PROOF_PURPOSES.capabilityDelegation] =
      [delegateKey.publicNode()];
    this.keys[delegateKey.id] = delegateKey;

    // Generate a capabilityInvocation purpose node using the previously
    // generated key
    invokeKey.id = this.generateKeyId({did, keyPair: invokeKey});
    this.doc[constants.PROOF_PURPOSES.capabilityInvocation] =
      [invokeKey.publicNode()];
    this.keys[invokeKey.id] = invokeKey;
  }

  /**
   * Generates a DID uri, either as a globally unique random string (uuid),
   * or from a given key pair (in case of cryptonym type did).
   *
   * @param {LDKeyPair} [keyPair] - KeyPair for the id.
   * @param {DIDType} [didType='nym'] - If 'nym', a key pair
   *   must also be passed in (to generate the did uri from).
   * @param {Mode} [mode='dev'] - The mode.
   *
   * @returns {string} DID uri.
   */
  generateId({keyPair, didType = 'nym', mode = constants.DEFAULT_MODE}) {
    if(didType === 'uuid') {
      const prefix = (mode === 'test') ? 'did:v1:test:' : 'did:v1:';
      return (prefix + 'uuid:' + uuid()).replace(/-/g, '');
    }

    if(!keyPair) {
      throw new TypeError('`keyPair` is required.');
    }

    // didType === 'nym'
    return this.createCryptonymDid({keyPair, mode});
  }

  generateKeyId({did, keyPair}) {
    return `${did}#${keyPair.fingerprint()}`;
  }

  /**
   * @param {string} proofPurpose - Proof purpose identifier.
   * @returns {Object|undefined} Returns undefined if not found.
   */
  getAllVerificationMethods(proofPurpose) {
    return this.doc[proofPurpose];
  }

  /**
   * Resolves with an LDKeyPair instance for the specified proof purpose.
   * If no methodId or methodIndex is given, the first available non-revoked
   * key is returned.
   *
   * @param {string} proofPurpose - For example, 'capabilityDelegation'.
   *
   * @param {string} [methodId] - Method id (DID with hash fragment, like
   *   `did:example:1234#<key fingerprint>`).
   * @param {number} [methodIndex] - The nth method in the set, zero-indexed.
   *
   * @returns {Object} Public method data.
   */
  getVerificationMethod({proofPurpose, methodId, methodIndex = 0}) {
    const methods = this.getAllVerificationMethods(proofPurpose);
    if(!methods) {
      throw new Error(`Method not found for proof purpose "${proofPurpose}".`);
    }

    let methodData;

    if(methodId) {
      methodData = methods.find(m => m.id === methodId);
    } else {
      methodData = methods[methodIndex];
    }
    // TODO: Check for revocation and expiration

    return methodData;
  }

  /**
   * Creates a cryptonym aka nym DID from a given key pair.
   *
   * @param {Object} options - Options for creating a cryptonym.
   * @param {LDKeyPair} options.keyPair - A keypair used to generate a `nym`.
   * @param {Mode} [options.mode='dev'] - Is this a test or production?
   */
  createCryptonymDid({keyPair, mode = constants.DEFAULT_MODE}) {
    const prefix = (mode === 'test') ? 'did:v1:test' : 'did:v1';

    return `${prefix}:nym:${keyPair.fingerprint()}`;
  }

  /**
   * Validates the DID of this document.
   * - Ensures DID contains 'test:' when running in 'test' mode and vice versa
   * - If cryptonym DIDs, ensures nym is validated against the invocation key
   * - Tests for invalid characters in the Specific ID.
   *
   * @see https://w3c-ccg.github.io/did-spec/#the-generic-did-scheme
   *
   * @param {Mode} [mode='dev'] - Mode: 'test'/'live' etc.
   *
   * @returns {Promise} Validator report
   *   {boolean} valid - true if the DID is valid
   *   {Error} error - included when `valid` is false.
   */
  async validateDid({mode = constants.DEFAULT_MODE} = {}) {
    // Make an exception for urn:uuid: type DID (elector pool doc, for example)
    if(this.id && this.id.startsWith('urn:uuid:')) {
      return {valid: true}; // short-circuit, UUID URNs are fine as is
    }

    const match = VERES_DID_REGEX.exec(this.id);

    if(!match) {
      return {
        error: new Error(`Invalid DID format: "${this.id}".`),
        valid: false
      };
    }

    // [2] undefined or 'test:'
    const didMode = match[2] && match[2].slice(0, -1);
    const type = match[3]; // nym / uuid
    const id = match[4];

    if(mode === 'test' && didMode !== 'test') {
      return {
        error: new Error(`DID is invalid for test mode: "${this.id}".`),
        valid: false
      };
    }

    if(mode !== 'test' && didMode === 'test') {
      return {
        error: new Error(
          `Test DID does not match mode "${mode}": "${this.id}".`),
        valid: false
      };
    }

    // ensure no invalid characters
    if((/[^A-Za-z0-9:\-.]+/).exec(id)) {
      return {
        error: new Error(
          `Specific id contains invalid characters: "${this.id}".`),
        valid: false
      };
    }

    // if type is 'uuid', no further validation necessary at the moment

    if(type === 'nym') {
      return this.validateCryptonymDid();
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
   * @returns {Promise} Validator report
   *   {boolean} valid - true if the DID is valid
   *   {Error} error - included when `valid` is false.
   */
  async validateCryptonymDid() {
    if(!this.doc.capabilityInvocation) {
      return {
        error: new Error('Cryptonym DID requires a capabilityInvocation key.'),
        valid: false
      };
    }

    const keyPair = await LDKeyPair.from(
      this.getVerificationMethod({proofPurpose: 'capabilityInvocation'}));

    if(!keyPair || !keyPair.publicKey) {
      return {
        error: new Error('Public key is required for cryptonym verification.'),
        valid: false
      };
    }

    const fingerprint = VERES_DID_REGEX.exec(this.id)[4];

    // verifyFingerprint has the same validator return signature
    return keyPair.verifyFingerprint(fingerprint);
  }

  /**
   * Validates the method IDs of this document. Method IDs must be of the
   * format: did#<multibase fingerprint>.
   *
   * @returns {Promise} Validator report
   *   {boolean} valid - true if the DID is valid
   *   {Error} error - included when `valid` is false.
   */
  async validateMethodIds() {
    for(const proofPurpose in constants.PROOF_PURPOSES) {
      const methods = this.getAllVerificationMethods(proofPurpose);
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

        if(parts[0] !== this.id) {
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

  /**
   * Starts observing changes made to the DID Document, in order to create a
   * diff patch to send to the ledger. Used for updating the doc.
   */
  observe() {
    if(this.observer) {
      this.unobserve();
    }
    this.observer = jsonpatch.observe(this.doc);
  }

  /**
   * Stops observing for changes.
   */
  unobserve() {
    if(!this.observer) {
      throw new Error('Not observing changes.');
    }
    jsonpatch.unobserve(this.doc, this.observer);
    this.observer = null;
  }

  /**
   * Stops observing for changes, and returns a changeset document (based on
   * JSON Patch), for sending updates to ledger.
   *
   * @returns {Object} The changes observed.
   */
  commit() {
    if(!this.observer) {
      throw new Error('Not observing changes.');
    }
    const patch = jsonpatch.generate(this.observer);

    this.unobserve();
    const sequence = this.meta.sequence;
    this.meta.sequence++;
    return {
      '@context': [
        constants.JSON_LD_PATCH_CONTEXT_V1_URL, {
          value: {
            '@id': 'jldp:value',
            '@context': didContexts
          }
        }
      ],
      patch,
      sequence,
      target: this.id,
    };
  }

  /**
   * Composes and returns a service id for a service name.
   *
   * @param {string} fragment - Part the later part of a service name.
   *
   * @returns {string} Service id.
   */
  serviceIdFor(fragment) {
    if(!fragment) {
      throw new Error('Invalid service fragment.');
    }
    return `${this.id}#${fragment}`;
  }

  /**
   * Finds a service endpoint in this did doc, given an id or a name.
   *
   * @param {Object} options - Options for finding a service.
   * @param {string} [options.fragment] - Part of a service id.
   * @param {string} [options.id] - A service id.
   *
   * @returns {Object} Returns a document.
   */
  findService({fragment, id}) {
    const serviceId = id || this.serviceIdFor(fragment);

    return jsonld
      .getValues(this.doc, 'service')
      .find(service => service.id === serviceId);
  }

  /**
   * Tests whether this did doc has a service endpoint (by fragment or id).
   * One of `id` or `fragment` is required.
   *
   * @param {Object} options - Options for hasService.
   * @param {string} [options.id] - A service id.
   * @param {string} [options.fragment] - A part of a service id.
   *
   * @returns {boolean} Do we have this serivce?
   */
  hasService({id, fragment}) {
    return !!this.findService({id, fragment});
  }

  /**
   * Adds a service endpoint to this did doc.
   * One of `id` or `fragment` is required.
   *
   * @param {Object} options - Options for adding a service.
   * @param {string} [options.fragment] - The later part of a service name.
   * @param {string} [options.id] - The full id of the service.
   * @param {string} [options.type] - URI (e.g. 'urn:AgentService').
   * @param {string} [options.endpoint] - A URI
   * (e.g. 'https://agent.example.com').
   */
  addService({fragment, endpoint, id, type}) {
    if(!!id === !!fragment) {
      throw new Error('Exactly one of `fragment` or `id` is required.');
    }
    if(id && !id.includes(':')) {
      throw new Error('Service `id` must be a URI.');
    }
    const serviceId = id || this.serviceIdFor(fragment);

    if(!type || !type.includes(':')) {
      throw new Error('Service `type` is required and must be a URI.');
    }
    if(!endpoint || !endpoint.includes(':')) {
      throw new Error('Service `endpoint` is required and must be a URI.');
    }

    if(this.findService({id, fragment})) {
      throw new Error('Service with that name or id already exists.');
    }

    jsonld.addValue(this.doc, 'service', {
      id: serviceId,
      serviceEndpoint: endpoint,
      type,
    }, {
      propertyIsArray: true
    });
  }

  /**
   * Removes a service endpoint from this did doc.
   * One of `id` or `fragment` is required.
   *
   * @param {Object} options - Options for remove service.
   * @param {string} [options.fragment] - The later part of a service name.
   * @param {string} [options.id] - The full id for a service.
   *
   * @returns {undefined}
   * TODO: return a boolean representing if the service was removed.
   */
  removeService({id, fragment}) {
    const serviceId = id || this.serviceIdFor(fragment);

    const services = jsonld
      .getValues(this.doc, 'service')
      .filter(service => service.id !== serviceId);
    if(services.length === 0) {
      jsonld.removeProperty(this.doc, 'service');
    } else {
      this.doc.service = services;
    }
  }

  addKey({key, proofPurpose, controller = this.id}) {
    // Add public key node to the DID Doc
    const keys = this.getAllVerificationMethods(proofPurpose);
    if(!keys) {
      throw new Error(`Keys not found for proofPurpose "${proofPurpose}".`);
    }
    keys.push(key.publicNode({controller}));

    // Add keypair (public + private) to non-exported key storage
    this.keys[key.id] = key;
  }

  /**
   * @param {LDKeyPair} key - The key to be removed.
   *
   * @returns {undefined} TODO: return a boolean representing removal success.
   */
  removeKey(key) {
    // check all proof purpose keys
    for(const proofPurposeType of Object.values(constants.PROOF_PURPOSES)) {
      this.doc[proofPurposeType] = this.doc[proofPurposeType]
        .filter(k => k.id !== key.id);
    }

    // also remove key from this doc's keys hash
    delete this.keys[key.id];
  }

  async exportKeys() {
    const exportedKeys = {};

    for(const keyId in this.keys) {
      const key = this.keys[keyId];
      exportedKeys[key.id] = await key.export();
    }

    return exportedKeys;
  }

  /**
   * Import keys from a json object.
   *
   * @param {Object} data - Parsed exported key JSON.
   * @param {Object} [options={}] - Options for the import.
   * @param {string} [options.passphrase] - A password.
   *
   * @returns {Promise} Can be awaited.
   */
  async importKeys(data = {}, options = {}) {
    for(const keyData of Object.values(data)) {
      const key = await LDKeyPair.from(keyData, options);
      this.keys[key.id] = key;
    }
  }

  toJSON() {
    return this.doc;
  }
}

module.exports = VeresOneDidDoc;
