/*!
 * Copyright (c) 2018-2021 Veres One Project. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const documentLoader = require('./documentLoader');

const VeresOneDriver = require('./VeresOneDriver');

module.exports = {
  constants,
  documentLoader,
  VeresOneDriver,
  driver: options => {
    return new VeresOneDriver(options);
  },
  VeresOneClient: require('./VeresOneClient'),
  VeresOneDidDoc: require('./VeresOneDidDoc')
};
