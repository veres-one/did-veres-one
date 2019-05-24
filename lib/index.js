/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const documentLoader = require('./documentLoader');

const VeresOne = require('./VeresOne');

module.exports = {
  constants,
  documentLoader,
  VeresOne,
  driver: options => {
    return new VeresOne(options);
  },
  VeresOneClient: require('./VeresOneClient'),
  VeresOneDidDoc: require('./VeresOneDidDoc')
};
