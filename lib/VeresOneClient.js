/*!
 * Copyright (c) 2018-2023 Veres One Project. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {
  createAuthzHeader, createSignatureString
} from '@digitalbazaar/http-signature-header';
import {httpClient} from '@digitalbazaar/http-client';
import {VeresOneClientError} from './VeresOneClientError.js';
import {WebLedgerClient} from 'web-ledger-client';

/**
 * @typedef Agent
 */
/**
 * @typedef LDKeyPair
 */

/**
 * Veres One Ledger Client.
 */
export class VeresOneClient {
  /**
   * @param {object} options - Options hashmap.
   * @param {string} options.hostname - Hostname of the ledger (points to a load
   *   balancer or a specific node).
   * @param {WebLedgerClient} [options.ledger] - Web Ledger Client instance.

   * @param {string} [options.mode] - One of 'dev'/'test'/'live'.
   * @param {Agent} [options.httpsAgent] - A NodeJS HTTPS Agent (`https.Agent`)
   *   instance.
   * @param {object} [options.logger=console] - Logger instance (with .log(),
   *   warn() and error() methods).
   */
  constructor({hostname, ledger, mode, httpsAgent, logger = console}) {
    this.hostname = hostname;
    if(!hostname) {
      throw new TypeError('The "hostname" parameter is required.');
    }

    this.ledger = ledger || new WebLedgerClient({httpsAgent, hostname, logger});
    this.mode = mode;
    this.logger = logger;
    this.httpsAgent = httpsAgent;
  }

  /**
   * Fetches a DID Document for a given DID. If it contains a #hash fragment,
   * it's likely a key id, so just return the subgraph, not the full doc.
   *
   * @param {object} options - Options hashmap.
   * @param {string} options.did - DID authority uri (without hash fragment).
   *
   * @returns {Promise<object>} Resolves to DID Document Fetch Result.
   */
  async get({did} = {}) {
    if(!did) {
      throw new TypeError('Invalid or missing DID URI.');
    }
    const {record: didDocument} = await this.ledger.getRecord({id: did});

    return didDocument;
  }

  /**
   * Get the status of a Document from the ledger Agent Status Service.
   *
   * @returns {Promise<object>} A document with a status.
   */
  async getStatus() {
    return this.ledger.getStatus();
  }

  async getTicketServiceProof({operation, ticketService}) {
    let result;
    try {
      result = await httpClient.post(ticketService, {
        json: {operation}, agent: this.httpsAgent
      });
    } catch(e) {
      const {response} = e;
      // if there is no response just rethrow the error
      if(!response) {
        throw e;
      }
      const error = new VeresOneClientError(
        'Error retrieving record.', 'NetworkError');
      error.details = {
        baseURL: ticketService, error: e, status: response.status, result
      };
      // errors in this range might contain response data
      if(response.status > 399 && response.status < 500) {
        // httpClient puts the error on the data object
        error.details.error = e.data || response.data || e;
      }
      throw error;
    }
    return result.data;
  }

  /**
   * Sends an operation to a Veres One accelerator.
   *
   * @param {object} options - The options.
   *
   * @param {object} options.operation - A WebLedgerOperation.
   *
   * @param {string} [options.hostname] - Accelerator hostname.
   * @param {string} [options.mode] - Used to determine default hostname.
   *
   * @param {LDKeyPair} [options.authKey] - Keys for signing the http request
   *   headers.
   *
   * @returns {Promise<object>} Response from a POST request.
   */
  // FIXME: currently unused, update this implementation after testnet v2
  async sendToAccelerator(options) {
    const {operation, authenticationKeyPair} = options;
    const hostname = options.hostname || this.hostname;

    const acceleratorPath = '/accelerator/proofs';
    const acceleratorUrl = `https://${hostname}${acceleratorPath}`;

    const headers = {
      Accept: 'application/ld+json, application/json',
      Host: hostname
    };

    if(!authenticationKeyPair) {
      throw new TypeError('Auth key is required for sending to accelerator.');
    }

    await VeresOneClient.signRequestHeaders({
      requestOptions: {
        url: acceleratorUrl,
        method: 'POST',
        headers
      },
      // signer
    });

    let result;
    try {
      result = await httpClient.post(acceleratorUrl, {
        json: {operation}, headers, agent: this.httpsAgent
      });
    } catch(e) {
      const {response} = e;
      // this ensures we don't hide errors such as invalid URL
      if(!response) {
        throw e;
      }
      const error = new VeresOneClientError(
        'Error retrieving record.', 'NetworkError');
      error.details = {
        baseURL: acceleratorUrl, error: e, status: response.status, result
      };
      // errors in this range might contain response data
      if(response.status > 399 && response.status < 500) {
        // httpClient puts the data directly on the error
        error.details.error = e.data || response.data || e;
      }
      throw error;
    }
    return result.data;
  }

  /**
   * Send an operation.
   *
   * @param {object} options - The options.
   * @param {object} options.operation - The operation to send.
   *
   * @returns {Promise<object>} - Send result.
   */
  async send({operation}) {
    return this.ledger.sendOperation({operation});
  }

  async wrap({didDocument, operationType}) {
    // FIXME: the web-ledger-client 1.0 APIs need some refinement, possibly
    // pass in recordPatch when it's an update operation?
    // if(operationType === 'create') {
    //   record = didDocument.toJSON();
    // } else {
    //   record = didDocument.commit();
    // }
    return this.ledger.wrap({record: didDocument, operationType});
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
