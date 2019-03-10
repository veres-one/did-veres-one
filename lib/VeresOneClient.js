/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */
'use strict';

const {create} = require('apisauce');
const https = require('https');
const {WebLedgerClient} = require('web-ledger-client');
const jsonld = require('jsonld');
jsonld.documentLoader = require('./documentLoader');
const VeresOneClientError = require('./VeresOneClientError');

const constants = require('./constants');

class VeresOneClient {
  /**
   * @param {Object} options - Options for the client.
   * @param {string} options.hostname
   * - Hostname of the ledger (points to a load balancer or a specific node).
   * @param {WebLedgerClient} options.ledger - Resolves DIDs.
   * @param {Mode} [options.mode='test'] - One of 'dev'/'test'/'live'.
   * Determines https agent settings
   * (does not reject unsigned certs in 'dev' mode, for example).
   * @param {Object} [options.logger] - Optional logger for the client.
   * @param {Agent} [options.httpsAgent] - An SSL capable http client.
   */
  constructor({hostname, ledger, mode, logger, httpsAgent}) {
    this.hostname = hostname;
    if(!hostname) {
      throw new Error('Missing ledger hostname.');
    }
    const strictSSL = (mode === 'dev') ? false : true;
    this.ledger = ledger ||
      new WebLedgerClient({httpsAgent, hostname, logger, strictSSL});

    this.mode = mode || constants.DEFAULT_MODE;
    this.logger = logger || console;

    this.httpsAgent = httpsAgent;
    if(mode === 'dev' && !this.httpsAgent) {
      this.httpsAgent = new https.Agent({rejectUnauthorized: false});
    }
  }

  /**
   * Fetches a DID Document for a given DID. If it contains a #hash fragment,
   * it's likely a key id, so just return the subgraph, not the full doc.
   *
   * @param {Object} options - Options for get.
   * @param {string} options.did - DID uri (possibly with hash fragment).
   *
   * @returns {Promise<Object>} Resolves to DID Document Fetch Result.
   */
  async get({did}) {
    if(!did) {
      throw new Error('Invalid or missing DID URI.');
    }
    const [docUri, hashFragment] = did.split('#');

    const result = await this.ledger.getRecord({id: docUri});

    const didDoc = result.record;

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
        throw new Error(
          `Failed to get subgraph within a DID Document, uri: "${did}".`
        );
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
   * @param {Object} options - Options for sendToAccelerator.
   *
   * @param {Object} options.operation - A WebLedgerOperation.
   *
   * @param {string} [options.hostname] - Accelerator hostname.
   * @param {string} [options.mode] - Used to determine default hostname.
   * @param {LDKeyPair} [options.authKey]
   * - Keys for signing the http request headers
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

    VeresOneClient.signRequestHeaders({
      path: acceleratorPath,
      headers,
      signHeaders: [ '(request-target)', 'date', 'host' ],
      keyId: authKey.id,
      key: authKey.privateKey,
      method: 'POST'
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
   * @param {Object} operation - An operation for the ledger.
   * @returns {Promise<Object>} Can be awaited.
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

  static signRequestHeaders({path, headers, signHeaders, keyId, key, method}) {
    // FIXME: replace http-signature with http-signature-middleware
    const httpSignature = require('http-signature');

    httpSignature.signRequest({
      getHeader: header => {
        // case insensitive lookup
        return headers[Object.keys(headers).find(
          key => key.toLowerCase() === header.toLowerCase())];
      },
      setHeader: (header, value) => {
        headers[header] = value;
      },
      method,
      path
    }, {
      headers: signHeaders,
      keyId,
      key
    });
  }
}

module.exports = VeresOneClient;
