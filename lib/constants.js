/*!
 * Copyright (c) 2018 Veres One Project. All rights reserved.
 */

module.exports = {
  JSON_LD_PATCH_CONTEXT_V1_URL: 'https://w3id.org/json-ld-patch/v1',
  VERES_ONE_CONTEXT_URL: 'https://w3id.org/veres-one/v1',
  WEB_LEDGER_CONTEXT_URL: 'https://w3id.org/webledger/v1',
  DID_CONTEXT_URL: 'https://w3id.org/did/v0.11',
  DEFAULT_KEY_TYPE: 'Ed25519VerificationKey2018',
  DEFAULT_MODE: 'dev',
  SUPPORTED_KEY_TYPES: ['RsaVerificationKey2018', 'Ed25519VerificationKey2018'],
  SUITES: {
    authentication: 'authentication',
    capabilityDelegation: 'capabilityDelegation',
    capabilityInvocation: 'capabilityInvocation'
  }
};
