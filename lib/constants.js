/*!
 * Copyright (c) 2018-2022 Veres One Project. All rights reserved.
 */
import * as didContext from 'did-context';
import * as jsonldPatchContext from 'json-ld-patch-context';
import * as veresOneContext from 'veres-one-context';
import * as webLedgerContext from 'web-ledger-context';
import * as zcapContext from '@digitalbazaar/zcap-context';

export const JSON_LD_PATCH_CONTEXT_V1_URL =
  jsonldPatchContext.constants.JSON_LD_PATCH_CONTEXT_V1_URL;
export const VERES_ONE_CONTEXT_URL =
  veresOneContext.constants.VERES_ONE_CONTEXT_V1_URL;
export const WEB_LEDGER_CONTEXT_URL =
  webLedgerContext.constants.WEB_LEDGER_CONTEXT_V1_URL;
export const DID_CONTEXT_URL = didContext.constants.DID_CONTEXT_URL;
export const ZCAP_CONTEXT_URL = zcapContext.constants.CONTEXT_URL;
export const DEFAULT_MODE = 'dev';
export const DEFAULT_DID_TYPE = 'nym'; // vs. 'uuid'
export const SUPPORTED_KEY_TYPES = ['Ed25519VerificationKey2020'];
export const VERIFICATION_RELATIONSHIPS = [
  'assertionMethod',
  'authentication',
  'capabilityDelegation',
  'capabilityInvocation',
  'keyAgreement'
];
