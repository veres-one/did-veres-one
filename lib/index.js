/*
 * Copyright (c) 2018 Veres One Project. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const documentLoader = require('./documentLoader');
const Injector = require('./Injector');
const injector = new Injector();

const jsigs = require('jsonld-signatures');
injector.use('jsonld-signatures', jsigs);

injector.env = {nodejs: true};

const VeresOne = require('./VeresOne');

module.exports = {
  constants,
  documentLoader,
  injector,
  VeresOne,
  veres: (options) => {
    return new VeresOne(options);
  },
  VeresOneClient: require('./VeresOneClient'),
  VeresOneDidDoc: require('./VeresOneDidDoc')
};
