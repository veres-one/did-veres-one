/*!
 * Copyright (c) 2018 Veres One Project. All rights reserved.
 */

module.exports = {
  VERES_ONE_CONTEXT_URL: 'https://w3id.org/veres-one/v1',
  DEFAULT_KEY_TYPE: 'Ed25519VerificationKey2018',
  DEFAULT_ENV: 'dev',
  SUPPORTED_KEY_TYPES: ['RsaVerificationKey2018', 'Ed25519VerificationKey2018'],
  SUITES: {
    authentication: 'authentication',
    capabilityDelegation: 'capabilityDelegation',
    capabilityInvocation: 'capabilityInvocation'
  }
};
