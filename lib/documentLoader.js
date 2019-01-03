/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const veresOneContext = require('veres-one-context');
const webLedgerContext = require('web-ledger-context');
const didContext = require('did-context');

const contextDocuments = new Map([
  [constants.DID_CONTEXT_URL, didContext],
  [constants.VERES_ONE_CONTEXT_URL, veresOneContext],
  [constants.WEB_LEDGER_CONTEXT_URL, webLedgerContext],
]);

module.exports = async (url) => {
  if(contextDocuments.has(url)) {
    return {
      contextUrl: null,
      document: contextDocuments.get(url),
      documentUrl: url
    };
  }
};
