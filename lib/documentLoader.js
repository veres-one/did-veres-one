/*!
 * Copyright (c) 2018-2022 Veres One Project. All rights reserved.
 */
import * as jsonldPatchContext from 'json-ld-patch-context';
import * as veresOneContext from 'veres-one-context';
import * as webLedgerContext from 'web-ledger-context';
import * as didContext from 'did-context';
import * as edContext from 'ed25519-signature-2020-context';
import * as x25519Context from 'x25519-key-agreement-2020-context';
import * as zcapContext from '@digitalbazaar/zcap-context';

const contextDocuments = new Map([
  ...didContext.contexts,
  ...jsonldPatchContext.contexts,
  ...veresOneContext.contexts,
  ...webLedgerContext.contexts,
  ...edContext.contexts,
  ...x25519Context.contexts,
  ...zcapContext.contexts
]);

export async function documentLoader(url) {
  if(contextDocuments.has(url)) {
    return {
      contextUrl: null,
      document: contextDocuments.get(url),
      documentUrl: url
    };
  }
  throw new Error(`"${url}" not found.`);
}
