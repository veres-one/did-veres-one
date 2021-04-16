/*!
 * Copyright (c) 2018-2021 Veres One Project. All rights reserved.
 */
'use strict';

const {CapabilityInvocation} = require('@digitalbazaar/zcapld');
const jsigs = require('jsonld-signatures');
const documentLoader = require('./documentLoader');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');
const constants = require('./constants');

/**
 * Attaches proofs to an operation by:
 *
 *  1. Using an Accelerator service, in which case an authorization DID
 *     Document is required beforehand (typically obtained in exchange for
 *     payment).
 *
 * @param operation {object} WebLedger operation
 *
 * @param options {object}
 *
 * @param [options.accelerator] {string} Hostname of accelerator to use
 * @param [options.authDoc] {VeresOneDidDoc} Auth DID Doc, required if using
 *   an accelerator service
 *
 * @param [options.notes]
 *
 * @returns {Promise<object>} - An operation document with proofs attached.
 */
async function attachProofs({operation, options, logger}) {
  const {didDocument} = options;

  if(options.accelerator) {
    // send operation to an accelerator for proof
    logger.log('Sending to accelerator for proof:', options.accelerator);
    operation = await attachAcceleratorProof({operation, ...options});
  } else {
    // send to ticket service for a proof
    operation = await attachTicketServiceProof({operation});
  }

  // get the capability invocation key, for signing the proof
  const invokeKeyNode = didDocument.getVerificationMethod({
    proofPurpose: 'capabilityInvocation'
  });
  const creator = invokeKeyNode.id;
  const invokeKey = didDocument.keys[invokeKeyNode.id];
  if(!invokeKey || !invokeKey.privateKey) {
    throw new Error('Invocation key required to perform a send.');
  }

  // attach capability invocation proof
  const capabilityAction =
    operation.type.startsWith('Create') ? 'create' : 'update';

  operation = await attachInvocationProof({
    operation,
    capability: didDocument.id,
    capabilityAction,
    creator,
    key: invokeKey
  });

  return operation;
}

/**
 * Sends a ledger operation to an accelerator.
 * Required when registering a DID Document (and not using a proof of work).
 *
 * @param options {object}
 *
 * @returns {Promise<object>} Response from an axios POST request
 */
async function attachAcceleratorProof({client, logger, ...options} = {}) {
  let authKey;

  try {
    authKey = options.authDoc.getVerificationMethod(
      {proofPurpose: 'authentication'});
  } catch(error) {
    throw new Error('Missing or invalid Authorization DID Doc.');
  }

  // send DID Document to a Veres One accelerator
  logger.log('Generating accelerator signature...');
  return client.sendToAccelerator({
    operation: options.operation,
    hostname: options.accelerator,
    env: options.mode,
    authKey
  });
}

/**
 * Adds an ocap invocation proof to an operation.
 *
 * @param {string} capability - capability url (did)
 * @param {string} capabilityAction - Here, 'create' or 'update'
 * @param {object} operation - WebLedger operation result (either from
 *   `attachAcceleratorProof()` or `attachTicketServiceProof()`)
 * @param {Ed25519KeyPair} key - invocation key
 *
 * @returns {Promise<object>}
 */
async function attachInvocationProof({
  capability, capabilityAction, operation, key
} = {}) {
  return jsigs.sign(operation, {
    documentLoader,
    compactProof: false,
    suite: new Ed25519Signature2020({key}),
    purpose: new CapabilityInvocation({capability, capabilityAction})
  });
}

/**
 * Adds a zcap delegation proof to a capability DID Document.
 */
async function attachDelegationProof({didDocument, creator, privateKeyPem}) {
  // FIXME: validate didDocument, creator, and privateKeyPem
  // TODO: support `signer` API as alternative to `privateKeyPem`
  return jsigs.sign(didDocument.doc, {
    algorithm: 'RsaSignature2018',
    creator,
    privateKeyPem,
    proof: {
      '@context': constants.VERES_ONE_CONTEXT_URL,
      proofPurpose: 'capabilityDelegation'
    }
  });
}

async function attachTicketServiceProof({client, ...operation} = {}) {
  const s = await client.getStatus();
  const ticketService = s.service['urn:veresone:ticket-service'].id;
  const result = await client.getTicketServiceProof(
    {operation, ticketService});
  return result.operation;
}

module.exports = {
  attachAcceleratorProof,
  attachDelegationProof,
  attachInvocationProof,
  attachProofs,
  attachTicketServiceProof
};
