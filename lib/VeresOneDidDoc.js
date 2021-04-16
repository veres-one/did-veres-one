/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */
'use strict';

const constants = require('./constants');

const jsonpatch = require('fast-json-patch');
const jsonld = require('jsonld');

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
}

module.exports = VeresOneDidDoc;
