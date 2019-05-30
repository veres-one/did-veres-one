/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const jsonldPatchContext = require('json-ld-patch-context');
const veresOneContext = require('veres-one-context');
const webLedgerContext = require('web-ledger-context');
const didContext = require('did-context');

const contextDocuments = new Map([
  [
    constants.DID_CONTEXT_URL,
    didContext.contexts.get(constants.DID_CONTEXT_URL)
  ],
  [
    constants.JSON_LD_PATCH_CONTEXT_V1_URL,
    jsonldPatchContext.contexts.get(constants.JSON_LD_PATCH_CONTEXT_V1_URL)
  ],
  [
    constants.VERES_ONE_CONTEXT_URL,
    veresOneContext.contexts.get(constants.VERES_ONE_CONTEXT_URL)
  ],
  [
    constants.WEB_LEDGER_CONTEXT_URL,
    webLedgerContext.contexts.get(constants.WEB_LEDGER_CONTEXT_URL)
  ],
]);

module.exports = async url => {
  if(contextDocuments.has(url)) {
    return {
      contextUrl: null,
      document: contextDocuments.get(url),
      documentUrl: url
    };
  }
  throw new Error(`"${url}" not found.`);
};
