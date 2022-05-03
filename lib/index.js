/*!
 * Copyright (c) 2018-2022 Veres One Project. All rights reserved.
 */
export * as constants from './constants.js';
export {documentLoader} from './documentLoader.js';
export {attachInvocationProof} from './attachProof.js';
export {VeresOneClient} from './VeresOneClient.js';
export {DidDocumentUpdater as VeresOneDidDoc} from './DidDocumentUpdater.js';
import {VeresOneDriver, fromNym, DID_REGEX} from './VeresOneDriver.js';

export {VeresOneDriver, fromNym, DID_REGEX};

export function driver(options) {
  return new VeresOneDriver(options);
}
