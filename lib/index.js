/*!
 * Copyright (c) 2018-2021 Veres One Project. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const documentLoader = require('./documentLoader');

const {VeresOneDriver, fromNym, DID_REGEX} = require('./VeresOneDriver');

module.exports = {
  constants,
  documentLoader,
  DID_REGEX,
  driver: options => {
    return new VeresOneDriver(options);
  },
  fromNym,
  VeresOneClient: require('./VeresOneClient'),
  VeresOneDidDoc: require('./DidDocumentUpdater'),
  VeresOneDriver
};
