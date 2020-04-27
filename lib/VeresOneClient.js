/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */
'use strict';

const {create} = require('apisauce');
const base64url = require('base64url-universal');
const httpSignatureHeader = require('http-signature-header');
const jsonld = require('jsonld');
const {WebLedgerClient} = require('web-ledger-client');
const VeresOneClientError = require('./VeresOneClientError');
const VeresOneDidDoc = require('./VeresOneDidDoc');
jsonld.documentLoader = require('./documentLoader');

const {createAuthzHeader, createSignatureString} = httpSignatureHeader;

const constants = require('./constants');

class VeresOneClient {
  /**
   * @param hostname {string} Hostname of the ledger (points to a load balancer
   *   or a specific node).
   * @param ledger {WebLedgerClient}

   * @param [mode='test'] {string} One of 'dev'/'test'/'live'. Determines https
   *   agent settings (does not reject unsigned certs in 'dev' mode, for
   *   example).
   * @param [logger]
   * @param [httpsAgent] {Agent} A NodeJS HTTPS Agent (`https.Agent`) instance.
   */
  constructor({hostname, ledger, mode, logger, httpsAgent}) {
    this.hostname = hostname;
    if(!hostname) {
      throw new Error('Missing ledger hostname.');
    }

    this.ledger = ledger || new WebLedgerClient({httpsAgent, hostname, logger});
    this.mode = mode || constants.DEFAULT_MODE;
    this.logger = logger || console;
    this.httpsAgent = httpsAgent;
  }

  /**
   * Fetches a DID Document for a given DID. If it contains a #hash fragment,
   * it's likely a key id, so just return the subgraph, not the full doc.
   *
   * @param did {string} DID uri (possibly with hash fragment)
   * @param forceConstruct {boolean} Forces deterministic construction of
   *   DID Document from cryptonym.
   *
   * @returns {Promise<object>} Resolves to DID Document Fetch Result
   */
  async get({did, forceConstruct = false}) {
    if(!did) {
      throw new Error('Invalid or missing DID URI.');
    }
    const [docUri, hashFragment] = did.split('#');
    const isNym = (did.startsWith('did:v1:nym:') ||
      did.startsWith('did:v1:test:nym:'));
    let result = {};
    let didDoc;

    // FIXME - remove, replace with cache
    if(isNym && forceConstruct) {
      didDoc = (await VeresOneDidDoc.fromNym({did: docUri})).doc;
    } else {
      try {
        result = await this.ledger.getRecord({id: docUri});
        didDoc = result.record;
      } catch(error) {
        if(error.name === 'NotFoundError' && isNym) {
          didDoc = (await VeresOneDidDoc.fromNym({did: docUri})).doc;
        } else {
          throw error;
        }
      }
    }

    const context = didDoc['@context'];

    if(!hashFragment) {
      // full DID Doc
      result.type = 'LedgerDidDocument';
      result.doc = didDoc;
    } else {
      // Request for a subgraph (likely just the key node)
      const map = await jsonld.createNodeMap(didDoc);
      const subGraph = map[did];
      if(!subGraph) {
        const error = new Error(
          `Failed to get subgraph within a DID Document, uri: "${did}".`
        );
        error.name = 'NotFoundError';
        throw error;
      }

      // result.type = 'Key'; <- not sure what this should be
      result.doc = await jsonld.compact(subGraph, context);
    }

    return result;
  }

  async getStatus() {
    return this.ledger.getStatus();
  }

  async getTicketServiceProof({operation, ticketService}) {
    const baseURL = ticketService;
    const ticketServiceApi = create({baseURL});
    const response = await ticketServiceApi.post(
      '/', {operation}, {httpsAgent: this.httpsAgent});
    if(response.problem) {
      const error = new VeresOneClientError(
        'Error retrieving record.', 'NetworkError');
      if(response.problem === 'CLIENT_ERROR') {
        error.details = {
          baseURL, error: response.data, status: response.status
        };
      } else {
        error.details = {
          baseURL, error: response.originalError, status: response.status
        };
      }
      throw error;
    }
    return response.data;
  }

  /**
   * Sends an operation to a Veres One accelerator.
   *
   * @param options {object}
   *
   * @param options.operation {object} WebLedgerOperation
   *
   * @param [options.hostname] {string} Accelerator hostname
   * @param [options.mode] {string} Used to determine default hostname
   *
   * Keys for signing the http request headers
   * @param [options.authKey] {LDKeyPair}
   *
   * @returns response {Promise<object>} from an axios POST request
   */
  // FIXME: currently unused, update this implementation after testnet v2
  async sendToAccelerator(options) {
    const {operation, authKey} = options;
    const hostname = options.hostname || this.hostname;

    const acceleratorPath = '/accelerator/proofs';
    const acceleratorUrl = `https://${hostname}${acceleratorPath}`;

    const headers = {
      Accept: 'application/ld+json, application/json',
      Host: hostname
    };

    if(!authKey || !authKey.privateKey) {
      throw new TypeError('Auth key is required for sending to accelerator.');
    }

    await VeresOneClient.signRequestHeaders({
      requestOptions: {
        url: acceleratorUrl,
        method: 'POST',
        headers
      },
      signer
    });

    const baseURL = acceleratorUrl;
    const acceleratorApi = create({baseURL});
    const response = acceleratorApi.post(
      '/', operation, {headers, httpsAgent: this.httpsAgent});

    if(response.problem) {
      const error = new VeresOneClientError(
        'Error retrieving record.', 'NetworkError');
      if(response.problem === 'CLIENT_ERROR') {
        error.details = {
          baseURL, error: response.data, status: response.status
        };
      } else {
        error.details = {
          baseURL, error: response.originalError, status: response.status
        };
      }
      throw error;
    }
    return response.data;
  }

  /**
   * @param operation {object}
   * @returns {Promise<object>}
   */
  async send({operation}) {
    return this.ledger.sendOperation({operation});
  }

  async wrap({didDocument, operationType}) {
    let record;
    // FIXME: the web-ledger-client 1.0 APIs need some refinement, possibly
    // pass in recordPatch when it's an update operation?
    if(operationType === 'create') {
      record = didDocument.toJSON();
    } else {
      record = didDocument.commit();
    }
    return this.ledger.wrap({record, operationType});
  }

  static async signRequestHeaders({requestOptions, signer}) {
    // TODO: update to use `(expires)` pseudo header or just use
    // `http-signature-zcap-invoke` if possible
    if(!requestOptions.headers.Expires) {
      // set expiration 10 minutes into the future
      const expires = new Date(Date.now() + 600000).toUTCString();
      requestOptions.headers.Expires = expires;
    }
    const includeHeaders = ['expires', 'host', '(request-target)'];
    const plaintext = createSignatureString({includeHeaders, requestOptions});
    const data = new TextEncoder().encode(plaintext);
    const signature = base64url.encode(await signer.sign({data}));

    const Authorization = createAuthzHeader({
      includeHeaders,
      keyId: signer.id,
      signature
    });

    requestOptions.headers = {...requestOptions.headers, Authorization};
  }
}

module.exports = VeresOneClient;
