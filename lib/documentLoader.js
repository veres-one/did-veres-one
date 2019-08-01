/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */
'use strict';

const jsonldPatchContext = require('json-ld-patch-context');
const veresOneContext = require('veres-one-context');
const webLedgerContext = require('web-ledger-context');
const didContext = require('did-context');

const contextDocuments = new Map([
  ...didContext.contexts,
  ...jsonldPatchContext.contexts,
  ...veresOneContext.contexts,
  ...webLedgerContext.contexts
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
