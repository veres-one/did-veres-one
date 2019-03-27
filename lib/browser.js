/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const documentLoader = require('./documentLoader');

const VeresOne = require('./browser/VeresOne');

module.exports = {
  constants,
  documentLoader,
  VeresOne,
  veres: options => {
    return new VeresOne(options);
  },
  VeresOneClient: require('./browser/VeresOneClient'),
  VeresOneDidDoc: require('./VeresOneDidDoc')
};
