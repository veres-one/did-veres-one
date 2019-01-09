/*!
 * Copyright (c) 2018 Veres One Project. All rights reserved.
 */
'use strict';

const axios = require('axios');
const https = require('https');
const WebLedgerClient = require('web-ledger-client');

const DEFAULT_MODE = 'test';

class VeresOneClient {
  /**
   * @param injector {Injector}
   *
   * @param hostname {string} Hostname of the ledger (points to a load balancer
   *   or a specific node).
   * @param ledger {WebLedgerClient}

   * @param [mode='test'] {string} One of 'dev'/'test'/'live'. Determines https
   *   agent settings (does not reject unsigned certs in 'dev' mode, for
   *   example).
   * @param [logger]
   * @param [httpsAgent] {Agent}
   */
  constructor({injector, hostname, ledger, mode, logger, httpsAgent}) {
    this.injector = injector;
    this.hostname = hostname;
    if(!hostname) {
      throw new Error('Missing ledger hostname.');
    }
    this.ledger = ledger ||
      new WebLedgerClient({injector, hostname, mode, logger, httpsAgent});

    this.mode = mode || DEFAULT_MODE;
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
   * @param did {string} DID uri (possibly with hash fragment)
   *
   * @returns {Promise<object>} Resolves to DID Document Fetch Result
   */
  async get({did}) {
    if(!did) {
      throw new Error('Invalid or missing DID URI.');
    }
    const [docUri, hashFragment] = did.split('#');

    const result = await this.ledger.get({id: docUri});

    const didDoc = result.record;

    const context = didDoc['@context'];

    if(!hashFragment) {
      // full DID Doc
      result.type = 'LedgerDidDocument';
      result.doc = didDoc;
    } else {
      // Request for a subgraph (likely just the key node)
      const jsonld = this.injector.use('jsonld');
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

  /**
   * Sends an operation to a Veres One accelerator.
   *
   * @param options {object}
   *
   * @param options.operation {object} WebLedgerOperation
   *
   * @param [options.hostname] {string} Accelerator hostname
   * @param [options.env] {string} Used to determine default hostname
   *
   * Keys for signing the http request headers
   * @param [options.authKey] {LDKeyPair}
   *
   * @returns response {Promise<object>} from an axios POST request
   */
  async sendToAccelerator(options) {
    const {operation, authKey} = options;
    const hostname = options.hostname || this.hostname;

    const acceleratorPath = '/accelerator/proofs';
    const acceleratorUrl = `https://${hostname}${acceleratorPath}`;

    const headers = {
      'Accept': 'application/ld+json, application/json',
      'Host': hostname
    };

    if(!authKey || !authKey.privateKey) {
      throw new Error("Auth key is required for sending to accelerator.");
    }

    VeresOneClient.signRequestHeaders({
      path: acceleratorPath,
      headers,
      signHeaders: [ '(request-target)', 'date', 'host' ],
      keyId: authKey.id,
      key: authKey.privateKey,
      method: 'POST'
    });

    const requestOptions = {
      url: acceleratorUrl,
      method: 'post',
      httpsAgent: this.httpsAgent,
      headers,
      data: operation
    };
    let response;

    try {
      response = await axios(requestOptions);
    } catch(error) {
      this.logger.error('Error sending request to accelerator:', requestOptions,
        error);
      throw error;
    }

    return response;
  }

  /**
   * @param operation {object}
   * @returns {Promise<object>}
   */
  async send({operation}) {
    return this.ledger.send({operation});
  }

  wrap({didDocument, operationType}) {
    let record;
    // FIXME: the web-ledger-client 1.0 APIs need some refinement, possibly
    // pass in recordPatch when it's an update operation?
    if(operationType === 'create') {
      record = didDocument.toJSON();
    } else {
      record = didDocument.commit();
    }
    const operation = this.ledger.constructor.wrap({record, operationType});
    return operation;
  }

  static signRequestHeaders({path, headers, signHeaders, keyId, key, method}) {
    const httpSignature = require('http-signature');

    httpSignature.signRequest({
      getHeader: (header) => {
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
