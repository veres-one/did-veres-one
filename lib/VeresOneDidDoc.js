/*!
 * Copyright (c) 2018 Veres One Project. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const {LDKeyPair} = require('crypto-ld');

const uuid = require('uuid/v4');
const jsonpatch = require('fast-json-patch');

const VERES_DID_REGEX = /^(did\:v1\:)(test\:)?(uuid|nym)\:(.+)/;
const didContexts = [
  constants.DID_CONTEXT_URL,
  constants.VERES_ONE_CONTEXT_URL
];

class VeresOneDidDoc {
  constructor(options = {}) {
    this.injector = options.injector;

    this.doc = options.doc || {'@context': didContexts};
    this.meta = options.meta || {sequence: 0};

    this.observer = null; // JSON Patch change observer

    // Includes private keys -- this property will not be serialized.
    this.keys = options.keys || {};
  }

  /**
   * Generates a new DID Document and initializes various authentication
   * and authorization suite keys.
   *
   * @param options
   * @param [options.injector]
   *
   * Params needed for DID generation:
   * @param [options.didType='nym'] {string} DID type, 'nym' or 'uuid'
   * @param [options.env] {string} 'dev'/'live' etc.
   *
   * Params needed for key generation:
   * @param [options.keyType] {string}
   * @param [options.passphrase] {string}
   *
   * @throws {Error}
   *
   * @returns {VeresOneDidDoc}
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
   * as well as authentication and authorization suites.
   * Only called when generating a new DID Doc (creates new keys, etc).
   *
   * @param [env]
   * @param [passphrase]
   * @param [keyType] {string}
   * @param [didType] {string}
   *
   * @returns {Promise}
   */
  async init({env, passphrase, didType, keyType = constants.DEFAULT_KEY_TYPE}) {
    const keyOptions = {injector: this.injector, type: keyType, passphrase};

    // Generate a capabilityInvocation key, to base the DID URI on
    const invokeKey = await LDKeyPair.generate(keyOptions);
    const did = this.generateId({keyPair: invokeKey, didType, env});
    this.doc.id = did;

    // Generate an authentication key pair and suite
    const authKey = await LDKeyPair.generate(keyOptions);
    authKey.id = this.generateKeyId({did, keyPair: authKey});
    this.doc[constants.SUITES.authentication] = [
      this.generateKeyObject({key: authKey})
    ];
    this.keys[authKey.id] = authKey;

    // Generate a capabilityDelegation key pair and suite
    const delegateKey = await LDKeyPair.generate(keyOptions);
    delegateKey.id = this.generateKeyId({did, keyPair: delegateKey});
    this.doc[constants.SUITES.capabilityDelegation] = [
      this.generateKeyObject({key: delegateKey})
    ];
    this.keys[delegateKey.id] = delegateKey;

    // Generate a capabilityInvocation suite (from an earlier generated key)
    invokeKey.id = this.generateKeyId({did, keyPair: invokeKey});
    this.doc[constants.SUITES.capabilityInvocation] = [
      this.generateKeyObject({key: invokeKey})
    ];
    this.keys[invokeKey.id] = invokeKey;
  }

  /**
   * Generates a DID uri, either as a globally unique random string (uuid),
   * or from a given key pair (in case of cryptonym type did).
   *
   * @param [keyPair] {LDKeyPair}
   * @param [didType='nym'] {string} 'uuid' or 'nym'. If 'nym', a key pair
   *   must also be passed in (to generate the did uri from).
   * @param [env='dev'] {string}
   *
   * @returns {string} DID uri
   */
  generateId({keyPair, didType = 'nym', env = 'dev'}) {
    if(didType === 'uuid') {
      const prefix = (env === 'live') ? 'did:v1:' : 'did:v1:test:';
      return (prefix + 'uuid:' + uuid()).replace(/-/g, '');
    }

    if(!keyPair) {
      throw new Error('Cannot generate a cryptonym DID without a key.');
    }

    // didType === 'nym'
    return this.createCryptonymDid({keyPair, env});
  }

  generateKeyId({did, keyPair}) {
    // `did` + multibase base58 (0x7a / z) encoding + key fingerprint
    return `${did}#z${keyPair.fingerprint()}`;
  }

  generateKeyObject({key}) {
    return key.publicNode({controller: this.id});
  }

  generateSuite({key, suiteId}) {
    const suiteType = key.type === 'Ed25519VerificationKey2018'
      ? 'Ed25519SignatureCapabilityAuthorization2018'
      : 'RsaSignatureCapabilityAuthorization2018';

    return {
      id: suiteId,
      type: suiteType,
      publicKey: [ key.publicNode({owner: this.id}) ]
    };
  }

  suiteForId(suiteId) {
    for(const suiteType in constants.SUITES) {
      const suites = this.doc[suiteType];
      const found = suites.find(s => s.id === suiteId);
      if(found) {
        return found;
      }
    }
  }

  /**
   * Creates a cryptonym DID from a given key pair.
   *
   * @param keyPair {LDKeyPair}
   * @param [env='dev'] {string}
   */
  createCryptonymDid({keyPair, env = 'dev'}) {
    const prefix = (env === 'live') ? 'did:v1' : 'did:v1:test';

    return `${prefix}:nym:` +
      'z' + // append multibase base58 (0x7a / z) encoding
      keyPair.fingerprint();
  }

  /**
   * Validates the DID of this document.
   * - Ensures DID contains 'test:' when running in 'test' mode and vice versa
   * - If cryptonym DIDs, ensures nym is validated against the invocation key
   * - Tests for invalid characters in the Specific ID
   *
   * @see https://w3c-ccg.github.io/did-spec/#the-generic-did-scheme
   *
   * @param [env='dev'] {string} Mode: 'test'/'live' etc
   */
  async validateDid({env = constants.DEFAULT_ENV} = {}) {
    // Make an exception for urn:uuid: type DID (elector pool doc, for example)
    if(this.id && this.id.startsWith('urn:uuid:')) {
      return; // short-circuit, UUID URNs are fine as is
    }

    const match = VERES_DID_REGEX.exec(this.id);

    if(!match) {
      throw new Error(`Invalid DID format: "${this.id}".`);
    }

    const mode = match[2] && match[2].slice(0, -1); // [2] undefined or 'test:'
    const type = match[3]; // nym / uuid
    const id = match[4];

    if(env === 'test' && mode !== 'test') {
      throw new Error(`DID is invalid for test mode: "${this.id}".`);
    }

    if(env !== 'test' && mode === 'test') {
      throw new Error(
        `Test DID does not match environment/mode "${env}": "${this.id}".`);
    }

    // ensure no invalid characters
    if((/[^A-Za-z0-9\:\-\.]+/).exec(id)) {
      throw new Error(`Specific id contains invalid characters: "${this.id}".`);
    }

    // if type is 'uuid', no further validation necessary at the moment

    if(type === 'nym') {
      return this.validateCryptonymDid();
    }
  }

  /**
   * Validates the (nym-based) DID of this document against invocation key.
   *
   * Note: Only validates the 'nym' part of the DID, assumes the overall
   * format was validated already (by `validateDid()`).
   *
   * @throws {Error} If this document is missing a capabilityInvocation key.
   * @throws {Error} If cryptonym is invalid or does not verify against key.
   */
  async validateCryptonymDid() {
    if(!this.doc.capabilityInvocation) {
      throw new Error('Cryptonym DID requires a capabilityInvocation key.');
    }

    const invokeKeyData = this.doc.capabilityInvocation[0];
    const keyPair = await LDKeyPair.from(invokeKeyData);

    if(!keyPair || !keyPair.publicKey) {
      throw new Error('Public key is required for cryptonym verification.');
    }

    const id = VERES_DID_REGEX.exec(this.id)[4];

    if(!id.startsWith('z')) {
      // Needs to start with multibase base58 encoding character (0x7a / z)
      throw new Error(`Cryptonym missing multibase encoding: "${this.id}".`);
    }

    const fingerprint = id.slice(1); // drop the leading 'z'

    // verify against the key
    if(!keyPair.verifyFingerprint(fingerprint)) {
      throw new Error(`Invalid DID - fingerprint does not verify against key.`);
    }
  }

  /**
   * Validates the key IDs of this document. Key IDs must be of the format:
   *
   * did#<multibase key fingerprint>
   *
   * @throws {Error} If this document's key IDs are invalid.
   */
  async validateKeyIds() {
    for(const id in this.keys) {
      const keyPair = this.keys[id];

      // note: Veres One DID documents presently do not permit keys from
      // other DID documents (or other HTTPS resources, etc)
      const parts = keyPair.id.split('#');
      if(parts.length !== 2) {
        throw new Error(
          'Invalid DID key ID; key ID must be of the form ' +
          '"<did>#<multibase key fingerprint>".');
      }

      if(parts[0] !== this.id) {
        throw new Error('Invalid DID key ID; key ID does not match the DID.');
      }

      if(!parts[1].startsWith('z')) {
        // needs to start with multibase base58 encoding character (0x7a / z)
        throw new Error(
          `Invalid DID key ID; missing multibase encoding: "${this.id}".`);
      }

      const fingerprint = parts[1].slice(1); // drop the leading 'z'

      // verify against the key
      if(!keyPair.verifyFingerprint(fingerprint)) {
        throw new Error(
          'Invalid DID key ID; fingerprint does not verify against key.');
      }
    }
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

    return {
      '@context': didContexts,
      target: this.id,
      sequence: this.meta.sequence,
      patch
    };
  }

  /**
   * Composes and returns a service id for a service name.
   *
   * @param serviceName {string}
   *
   * @returns {string} Service id
   */
  serviceIdFor(serviceName) {
    if(!serviceName) {
      throw new Error('Invalid service name.');
    }

    return this.id + ';service=' + encodeURIComponent(serviceName);
  }

  /**
   * Finds a service endpoint in this did doc, given an id or a name.
   *
   * @param [id] {string}
   * @param [name] {string}
   *
   * @returns {object}
   */
  findService({id, name}) {
    const jsonld = this.injector.use('jsonld');

    const serviceId = id || this.serviceIdFor(name);

    return jsonld
      .getValues(this.doc, 'service')
      .find(service => service.id === serviceId);
  }

  /**
   * Tests whether this did doc has a service endpoint (by name or id).
   * One of `id` or `name` is required.
   *
   * @param [id] {string}
   * @param [name] {string}
   *
   * @returns {boolean}
   */
  hasService({id, name}) {
    return !!this.findService({id, name});
  }

  /**
   * Adds a service endpoint to this did doc.
   * One of `id` or `name` is required.
   *
   * @param [id] {string}
   * @param [name] {string}
   * @param type {string} Endpoint type (e.g. 'AgentService')
   * @param endpoint {string} Endpoint uri (e.g. 'https://agent.example.com')
   * @param [options] {object} Any additional properties of endpoint
   */
  addService({id, name, type, endpoint, ...options}) {
    const jsonld = this.injector.use('jsonld');

    const serviceId = id || this.serviceIdFor(name);

    if(!type) {
      throw new Error('Service endpoint type is required.');
    }
    if(!endpoint) {
      throw new Error('Service endpoint uri is required.');
    }

    if(this.findService({id, name})) {
      throw new Error('Service with that name or id already exists.');
    }

    jsonld.addValue(this.doc, 'service', {
      id: serviceId,
      serviceEndpoint: endpoint,
      type,
      ...options
    }, {
      propertyIsArray: true
    });
  }

  /**
   * Removes a service endpoint from this did doc.
   * One of `id` or `name` is required.
   *
   * @param [id] {string}
   * @param [name] {string}
   */
  removeService({id, name}) {
    const jsonld = this.injector.use('jsonld');

    const serviceId = id || this.serviceIdFor(name);

    const services = jsonld
      .getValues(this.doc, 'service')
      .filter(service => service.id !== serviceId);
    if(services.length === 0) {
      jsonld.removeProperty(this.doc, 'service');
    } else {
      this.doc.service = services;
    }
  }

  addKey({key, suiteId, owner = this.id}) {
    // Add public key node to the DID Doc
    const suite = this.suiteForId(suiteId);
    if(!suite) {
      throw new Error(`Suite not found for suite id "${suiteId}".`);
    }
    suite.publicKey.push(key.publicNode({owner}));

    // Add keypair (public + private) to non-exported key storage
    this.keys[key.id] = key;
  }

  removeKey(key) {
    const jsonld = this.injector.use('jsonld');
    // check all suites
    for(const suiteType in constants.SUITES) {
      for(const suiteParams of jsonld.getValues(this.doc, suiteType)) {
        suiteParams.publicKey = jsonld.getValues(suiteParams, 'publicKey')
          .filter(k => k.id !== key.id);
      }
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
   * @param data {object} Parsed exported key JSON
   * @param [options={}] {object}
   * @param [options.passphrase] {string}
   *
   * @returns {Promise}
   */
  async importKeys(data = {}, options = {}) {
    for(const keyData of Object.values(data)) {
      const key = await LDKeyPair.from(keyData,
        {injector: this.injector, ...options});
      this.keys[key.id] = key;
    }
  }

  toJSON() {
    return this.doc;
  }
}

module.exports = VeresOneDidDoc;
