/*!
 * Copyright (c) 2018-2022 Veres One Project. All rights reserved.
 */
import * as constants from './constants.js';
import {DID_DOC_CONTEXTS} from './VeresOneDriver.js';

import {
  generate as jsonPatchGenerate,
  observe as jsonPatchObserve,
  unobserve as jsonPatchUnobserve
} from 'fast-json-patch/index.mjs';

export class DidDocumentUpdater {
  constructor({didDocument, meta}) {
    this.didDocument = didDocument;
    this.meta = meta || {sequence: 0};

    this.observer = null; // JSON Patch change observer
    this.observe();
  }

  /**
   * Starts observing changes made to the DID Document, in order to create a
   * diff patch to send to the ledger. Used for updating the doc.
   */
  observe() {
    if(this.observer) {
      this.unobserve();
    }
    this.observer = jsonPatchObserve(this.didDocument);
  }

  /**
   * Stops observing for changes.
   */
  unobserve() {
    if(!this.observer) {
      throw new Error('Not observing changes.');
    }
    jsonPatchUnobserve(this.didDocument, this.observer);
    this.observer = null;
  }

  /**
   * Stops observing for changes, and returns a changeset document (based on
   * JSON Patch), for sending updates to ledger.
   *
   * @returns {object} A changeset document.
   */
  commit() {
    if(!this.observer) {
      throw new Error('Not observing changes.');
    }
    const patch = jsonPatchGenerate(this.observer);

    this.unobserve();
    const sequence = this.meta.sequence;
    this.meta.sequence++;
    return {
      '@context': [
        constants.JSON_LD_PATCH_CONTEXT_V1_URL, {
          value: {
            '@id': 'jldp:value',
            '@context': DID_DOC_CONTEXTS
          }
        }
      ],
      patch,
      sequence,
      target: this.didDocument.id,
    };
  }
}
