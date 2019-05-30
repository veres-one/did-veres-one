/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */
'use strict';

const jsonldPatchContext = require('json-ld-patch-context');
const webLedgerContext = require('web-ledger-context');

module.exports = {
  JSON_LD_PATCH_CONTEXT_V1_URL:
    jsonldPatchContext.constants.JSON_LD_PATCH_CONTEXT_V1_URL,
  VERES_ONE_CONTEXT_URL: 'https://w3id.org/veres-one/v1',
  WEB_LEDGER_CONTEXT_URL: webLedgerContext.constants.WEB_LEDGER_CONTEXT_V1_URL,
  DID_CONTEXT_URL: 'https://w3id.org/did/v0.11',
  DEFAULT_KEY_TYPE: 'Ed25519VerificationKey2018',
  DEFAULT_MODE: 'dev',
  SUPPORTED_KEY_TYPES: ['RsaVerificationKey2018', 'Ed25519VerificationKey2018'],
  PROOF_PURPOSES: {
    authentication: 'authentication',
    capabilityDelegation: 'capabilityDelegation',
    capabilityInvocation: 'capabilityInvocation'
  }
};
