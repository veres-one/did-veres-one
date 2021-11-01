/*!
 * Copyright (c) 2018-2021 Veres One Project. All rights reserved.
 */
'use strict';

const jsonldPatchContext = require('json-ld-patch-context');
const veresOneContext = require('veres-one-context');
const webLedgerContext = require('web-ledger-context');
const didContext = require('did-context');
const edContext = require('ed25519-signature-2020-context');
const x25519Context = require('x25519-key-agreement-2020-context');
const zcapContext = require('zcap-context');
const {ZCAP_ROOT_PREFIX} = require('./constants');

const contextDocuments = new Map([
  ...didContext.contexts,
  ...jsonldPatchContext.contexts,
  ...veresOneContext.contexts,
  ...webLedgerContext.contexts,
  ...edContext.contexts,
  ...x25519Context.contexts,
  ...zcapContext.contexts
]);

module.exports = async url => {
  if(contextDocuments.has(url)) {
    return {
      contextUrl: null,
      document: contextDocuments.get(url),
      documentUrl: url
    };
  }
  if(url.startsWith(ZCAP_ROOT_PREFIX)) {
    const id = decodeURIComponent(url.substr(ZCAP_ROOT_PREFIX.length));
    return {
      contextUrl: null,
      document: {
        '@context': zcapContext.CONTEXT_URL,
        id: url,
        controller: id,
        invocationTarget: id
      },
      documentUrl: url
    };
  }
  throw new Error(`"${url}" not found.`);
};
