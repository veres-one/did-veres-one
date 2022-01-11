/*!
 * Copyright (c) 2018-2022 Veres One Project. All rights reserved.
 */
'use strict';

const didContext = require('did-context');
const jsonldPatchContext = require('json-ld-patch-context');
const veresOneContext = require('veres-one-context');
const webLedgerContext = require('web-ledger-context');
const zcapContext = require('@digitalbazaar/zcap-context');

module.exports = {
  JSON_LD_PATCH_CONTEXT_V1_URL:
    jsonldPatchContext.constants.JSON_LD_PATCH_CONTEXT_V1_URL,
  VERES_ONE_CONTEXT_URL: veresOneContext.constants.VERES_ONE_CONTEXT_V1_URL,
  WEB_LEDGER_CONTEXT_URL: webLedgerContext.constants.WEB_LEDGER_CONTEXT_V1_URL,
  DID_CONTEXT_URL: didContext.constants.DID_CONTEXT_URL,
  ZCAP_CONTEXT_URL: zcapContext.constants.CONTEXT_URL,
  DEFAULT_MODE: 'dev',
  DEFAULT_DID_TYPE: 'nym', // vs. 'uuid'
  SUPPORTED_KEY_TYPES: ['Ed25519VerificationKey2020'],
  VERIFICATION_RELATIONSHIPS: [
    'assertionMethod',
    'authentication',
    'capabilityDelegation',
    'capabilityInvocation',
    'keyAgreement'
  ]
};
