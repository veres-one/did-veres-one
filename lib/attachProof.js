/*!
 * Copyright (c) 2018-2021 Veres One Project. All rights reserved.
 */
'use strict';

const {CapabilityInvocation} = require('@digitalbazaar/zcapld');
const jsigs = require('jsonld-signatures');
const documentLoader = require('./documentLoader');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');

/**
 * Attaches proofs to an operation by:
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
 * @param {string} options.did - Id of the DID Document to register.
 * @param {VeresOneClient} options.client - Veres One client instance.
 * @param {object} options.logger - Logger object.
 *
 * Either a `capabilityInvocationKeyPair` instance or a signer is required:
 * @param {LDKeyPair} [options.capabilityInvocationKeyPair] - Either a
 *   capabilityInvocation public/private key pair instance, or a signer type
 *   object from a KMS (`{sign: Function, id: string}`). Used to sign the
 *   capability invocation proof.
 * @param {{sign: Function, id: string}} [options.signer] - A signer-type
 *   object (from a KMS).
 *
 * Needed for Accelerator only (not currently used?):
 * @param {string}  [options.accelerator] - Hostname of accelerator to use.
 * @param {LDKeyPair} [options.authenticationKeyPair] - authentication
 *   public/private key pair instance (required for using accelerator).
 * @param {object} [options.authDoc] - Auth DID Doc, required if using
 *   an accelerator service.
 * @param {string} options.mode - Ledger mode ('test', 'live' etc).
 *
 * @returns {Promise<object>} - An operation document with proofs attached.
 */
async function attachProofs(operation, {
  did, client, capabilityInvocationKeyPair = {}, signer = {}, logger,
  authenticationKeyPair, authDoc, accelerator, mode
} = {}) {
  if(accelerator) {
    // send operation to an accelerator for proof
    logger.log('Sending to accelerator for proof:', accelerator);
    operation = await attachAcceleratorProof(operation, {
      client, authenticationKeyPair, capabilityInvocationKeyPair, accelerator,
      authDoc, mode, logger
    });
  } else {
    // send to ticket service for a proof
    operation = await attachTicketServiceProof({client, ...operation});
  }

  const controller = capabilityInvocationKeyPair.id || signer.id;
  // attach capability invocation proof
  operation = await attachInvocationProof(operation, {
    capability: did,
    capabilityAction: operation.type,
    controller,
    key: capabilityInvocationKeyPair,
    signer
  });

  return operation;
}

/**
 * Sends a ledger operation to an accelerator.
 * Required when registering a DID Document (and not using a proof of work).
 *
 * @param {object} operation - WebLedger operation.
 * @param {string} operation.type - Operation type 'create', 'update' etc.
 *
 * @param {object} options - Options hashmap.
 * @param {VeresOneClient} options.client - Veres One client instance.
 * @param {LDKeyPair} options.authenticationKeyPair - An authentication
 *   public/private key pair instance. Required for using accelerator.
 * @param {string}  [options.accelerator] - Hostname of accelerator to use.
 * @param {string} options.mode - Ledger mode ('test', 'live' etc).
 * @param {object} options.logger - Logger object.
 *
 * @returns {Promise<object>} Response from an axios POST request
 */
async function attachAcceleratorProof(operation, {
  client, authenticationKeyPair, accelerator, mode, logger
} = {}) {
  // send DID Document to a Veres One accelerator
  logger.log('Generating accelerator signature...');
  return client.sendToAccelerator({
    operation,
    hostname: accelerator,
    env: mode,
    authKey: authenticationKeyPair
  });
}

/**
 * Adds a zcap-style invocation proof to an operation.
 *
 * @param {object} operation - WebLedger operation.
 *
 * @param {object} options - Options hashmap.
 * @param {string} capability - Capability (DID) url.
 * @param {string} capabilityAction - 'create' / 'update'.
 *
 * Either a key pair instance or a signer object (from a KMS) is required:
 * @param {LDKeyPair} [options.key] - A capabilityInvocation
 *   public/private key pair instance.
 * @param {{sign: Function, id: string}} [options.signer] - A signer-type object
 *   such as that provided by a KMS.
 *
 * @returns {Promise<object>}
 */
async function attachInvocationProof(operation, {
  capability, capabilityAction, key, signer
} = {}) {
  return jsigs.sign(operation, {
    documentLoader,
    suite: new Ed25519Signature2020({key, signer}),
    purpose: new CapabilityInvocation({capability, capabilityAction})
  });
}

async function attachTicketServiceProof({client, ...operation} = {}) {
  const s = await client.getStatus();
  const ticketService = s.service['urn:veresone:ticket-service'].id;
  const result = await client.getTicketServiceProof({
    operation, ticketService
  });
  return result.operation;
}

module.exports = {
  attachAcceleratorProof,
  attachInvocationProof,
  attachProofs,
  attachTicketServiceProof
};
