/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const {LDKeyPair} = require('crypto-ld');

const uuid = require('uuid-random');
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
   * @param options
   *
   * Params needed for DID generation:
   * @param [options.didType='nym'] {string} DID type, 'nym' or 'uuid'
   * @param [options.mode] {string} 'dev'/'live' etc.
   *
   * Optionally pass in an invocation key to use to generate the DID:
   * @param [options.invokeKey] {LDKeyPair}
   * @param [options.authKey] {LDKeyPair}
   * @param [options.delegateKey] {LDKeyPair}
   * @param [options.assertionKey] {LDKeyPair}
   *
   * Params needed for key generation:
   * @param [options.keyType] {string}
   * @param [options.passphrase] {string}
   *
   * @throws {Error}
   *
   * @returns {Promise<VeresOneDidDoc>}
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
   * Creates a DID Document from a cryptonym DID.
   *
   * @param {string} did
   * @returns {Promise<VeresOneDidDoc>}
   */
  static async fromNym({did}) {
    let invokeKey, mode;
    try {
      // Re-hydrate capabilityInvocation public key from fingerprint
      const match = VERES_DID_REGEX.exec(did);
      mode = match[2] && match[2].slice(0, -1); // 'test' or otherwise
      const fingerprint = match[4];
      invokeKey = LDKeyPair.fromFingerprint({fingerprint});
    } catch(error) {
      throw new Error(`Invalid cryptonym: ${did}`);
    }
    // Use that key to deterministically construct a DID Doc
    return await VeresOneDidDoc.generate({
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
   * @param [key] {LDKeyPair} - Required for generating a cryptonym DID.
   * @param [didType='nym'] {string} 'uuid' or 'nym'. If 'nym', a key pair
   *   must also be passed in (to generate the did uri from).
   * @param [mode='dev'] {string}
   *
   * @returns {string} DID uri
   */
  static generateDid({
    key, didType = constants.DEFAULT_DID_TYPE, mode = constants.DEFAULT_MODE}) {
    if(didType === 'uuid') {
      const prefix = (mode === 'test') ? 'did:v1:test:' : 'did:v1:';
      return (prefix + 'uuid:' + uuid()).replace(/-/g, '');
    }

    // didType === 'nym'
    if(!key) {
      throw new TypeError('`key` is required to generate cryptonym DID.');
    }

    return VeresOneDidDoc.createCryptonymDid({key, mode});
  }

  static generateKeyId({did, keyPair}) {
    return `${did}#${keyPair.fingerprint()}`;
  }

  /**
   * Creates a cryptonym DID from a given key pair.
   *
   * @param key {LDKeyPair}
   * @param [mode='dev'] {string}
   */
  static createCryptonymDid({key, mode = constants.DEFAULT_MODE}) {
    const prefix = (mode === 'test') ? 'did:v1:test' : 'did:v1';

    return `${prefix}:nym:${key.fingerprint()}`;
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
   * @param [mode] {string} 'dev' / 'test' etc.
   * @param [passphrase]
   * @param [keyType] {string}
   * @param [didType] {string}
   * @param [invokeKey] {LDKeyPair}
   * @param [authKey] {LDKeyPair}
   * @param [delegateKey] {LDKeyPair}
   * @param [assertionKey] {LDKeyPair}
   *
   * @returns {Promise}
   */
  async init({
    mode, passphrase, didType, keyType = constants.DEFAULT_KEY_TYPE, invokeKey,
    authKey, delegateKey, assertionKey
  }) {
    const keyOptions = {type: keyType, passphrase};

    // Generate a capabilityInvocation key pair
    if(!invokeKey) {
      invokeKey = await LDKeyPair.generate(keyOptions);
    }

    // Use the generated capabilityInvocation key to base the DID URI on
    const did = VeresOneDidDoc.generateDid({key: invokeKey, didType, mode});
    this.doc.id = did;

    // Assign the DID as a default controller for the keys
    keyOptions.controller = did;

    // Now that we have a DID, generate the other keys

    // Generate an authentication key pair
    if(!authKey) {
      authKey = await LDKeyPair.generate(keyOptions);
    }

    // Generate a capabilityDelegation key pair
    if(!delegateKey) {
      delegateKey = await LDKeyPair.generate(keyOptions);
    }

    // Generate an assertionMethod key pair
    if(!assertionKey) {
      assertionKey = await LDKeyPair.generate(keyOptions);
    }

    for(const keyPair of [authKey, invokeKey, delegateKey, assertionKey]) {
      keyPair.controller = did;
      if(!keyPair.id) {
        keyPair.id = VeresOneDidDoc.generateKeyId({did, keyPair});
      }
    }

    // Generate an authentication proof purpose node
    this.doc[constants.PROOF_PURPOSES.authentication] =
      [authKey.publicNode()];
    this.keys[authKey.id] = authKey;

    // Generate a capabilityInvocation proof purpose node
    this.doc[constants.PROOF_PURPOSES.capabilityInvocation] =
      [invokeKey.publicNode()];
    this.keys[invokeKey.id] = invokeKey;

    // Generate a capabilityDelegation proof purpose node
    this.doc[constants.PROOF_PURPOSES.capabilityDelegation] =
      [delegateKey.publicNode()];
    this.keys[delegateKey.id] = delegateKey;

    // Generate an assertionMethod purpose node
    this.doc[constants.PROOF_PURPOSES.assertionMethod] =
      [assertionKey.publicNode()];
    this.keys[assertionKey.id] = assertionKey;
  }

  /**
   * Returns all verification methods (keys) for a given proof purpose.
   *
   * @param proofPurpose {string} proof purpose identifier
   * @returns {object|undefined}
   */
  getAllVerificationMethods(proofPurpose) {
    return this.doc[proofPurpose];
  }

  /**
   * Resolves with the node for the verification method for the specified proof
   * purpose (from which you can create an LDKeyPair instance).
   * If no methodId or methodIndex is given, the first available non-revoked
   * key is returned.
   *
   * This is useful for when you know the _purpose_ of a key, but not its id.
   * (If you know the key id but need to find its purpose, use
   * `findVerificationMethod()` instead.)
   *
   * Usage:
   *
   *   ```
   *   const method = didDoc.getVerificationMethod(
   *     {proofPurpose: 'assertionMethod'});
   *
   *   // Now you can either create a key pair
   *   const keyPair = new LDKeyPair(method);
   *
   *   // Or get the key directly from the doc's key cache
   *   const keyPair = didDoc.keys[method.id];
   *   ```
   *
   * @param proofPurpose {string} For example, 'capabilityDelegation'
   *
   * @param [methodId] {string} method id (DID with hash fragment, like
   *   `did:example:1234#<key fingerprint>`)
   * @param [methodIndex] {number} The nth method in the set, zero-indexed.
   *
   * @returns {object} Public method data
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
   * Alias for `findVerificationMethod()`.
   * Example:
   * ```
   * findKey({id: 'did:ex:123#abcd'})
   * // ->
   * // {proofPurpose: 'authentication', key: { ... }}
   * ```
   * @returns {{proofPurpose: string, key: object}}
   */
  findKey({id}) {
    const {proofPurpose, method: key} = this.findVerificationMethod({id});
    return {proofPurpose, key};
  }

  /**
   * Finds a verification method for a given id, and returns it along with the
   * proof purpose in which it resides. (Note that if a key is included in
   * multiple proof purpose sections, the first occurrence is returned.)
   *
   * Useful for operations like rotate, since you need to know which proof
   * purpose section to add a new key to (after removing the old one).
   *
   * Example:
   * ```
   * findVerificationMethod({id: 'did:ex:123#abcd'})
   * // ->
   * // {proofPurpose: 'authentication', method: { ... }}
   * ```
   *
   * @param {string} id - Verification method id.
   * @returns {{proofPurpose: string, method: object}}
   */
  findVerificationMethod({id}) {
    if(!id) {
      throw new Error('Method id is required.');
    }

    for(const proofPurpose in constants.PROOF_PURPOSES) {
      let method;
      try {
        method = this.getVerificationMethod({proofPurpose, methodId: id});
        if(method) {
          return {proofPurpose, method};
        }
      } catch(error) {
        // Method not found for that purpose, continue searching
      }
    }
    return {};
  }

  /**
   * Validates the DID of this document.
   * - Ensures DID contains 'test:' when running in 'test' mode and vice versa
   * - If cryptonym DIDs, ensures nym is validated against the invocation key
   * - Tests for invalid characters in the Specific ID
   *
   * @see https://w3c-ccg.github.io/did-spec/#the-generic-did-scheme
   *
   * @param [mode='dev'] {string} Mode: 'test'/'live' etc
   *
   * @returns {Promise} validator report
   *   {boolean} valid - true if the DID is valid
   *   {Error} error - included when `valid` is false
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
   * @returns {Promise} validator report
   *   {boolean} valid - true if the DID is valid
   *   {Error} error - included when `valid` is false
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
   * format: did#<multibase fingerprint>
   *
   * @returns {Promise} validator report
   *   {boolean} valid - true if the DID is valid
   *   {Error} error - included when `valid` is false
   */
  async validateMethodIds() {
    for(const proofPurpose in constants.PROOF_PURPOSES) {
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
   * @returns {object}
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
   * @param {string} serviceName
   *
   * @returns {string} Service id
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
   * @param {string} [fragment]
   * @param {string} [id]
   *
   * @returns {object}
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
   * @param {string} [id]
   * @param {string} [name]
   *
   * @returns {boolean}
   */
  hasService({id, fragment}) {
    return !!this.findService({id, fragment});
  }

  /**
   * Adds a service endpoint to this did doc.
   * One of `id` or `fragment` is required.
   *
   * @param {string} [fragment]
   * @param {string} [id]
   * @param {string} type URI (e.g. 'urn:AgentService')
   * @param {string} endpoint  URI (e.g. 'https://agent.example.com')
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
   * @param {string} [fragment]
   * @param {string} [id]
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
   * @param key {LDKeyPair}
   */
  removeKey(key) {
    // check all proof purpose keys
    for(const proofPurposeType of Object.values(constants.PROOF_PURPOSES)) {
      if(this.doc[proofPurposeType]) {
        this.doc[proofPurposeType] = this.doc[proofPurposeType]
          .filter(k => k.id !== key.id);
      }
    }

    // also remove key from this doc's keys hash
    delete this.keys[key.id];
  }

  /**
   * Rotates a key in this did document (removes the old one, and generates and
   * adds a new one to the same proof purpose section). Key id is not re-used.
   *
   * One of the following is required:
   * @param {LDKeyPair} [key] - Key object (with an .id)
   * @param {string} [id] - Key id
   *
   * @param {string} [passphrase] - Optional passphrase to encrypt the new key.
   *
   * @returns {Promise<LDKeyPair>} Returns new key (after removing the old one)
   */
  async rotateKey({key, id, passphrase}) {
    if(!key && !id) {
      throw new Error('A key id or key object is required to rotate.');
    }
    const keyId = id || key.id;
    const {proofPurpose, key: oldKey} = this.findKey({id: keyId});
    if(!oldKey) {
      throw new Error(`Key ${keyId} is not found in did document.`);
    }
    const keyType = oldKey.type;
    const controller = oldKey.controller;

    // Start the observer if necessary (generates patches for update())
    if(!this.observer) {
      this.observe();
    }

    // First, remove the old key
    this.removeKey({id: keyId});

    // Generate an add a new key to the same proof purpose (key id not re-used)
    const newKey = await LDKeyPair.generate({type: keyType, passphrase});
    newKey.id = VeresOneDidDoc.generateKeyId({did: this.id, keyPair: newKey});
    newKey.controller = controller;

    this.addKey({key: newKey, proofPurpose, controller});

    return newKey;
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
   * @param data {object} Parsed exported key JSON
   * @param [options={}] {object}
   * @param [options.passphrase] {string}
   *
   * @returns {Promise}
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
