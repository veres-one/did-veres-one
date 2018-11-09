/*
 * Copyright (c) 2018 Veres One Project. All rights reserved.
 */
'use strict';

const Injector = require('./Injector');
const injector = new Injector();

const jsigs = require('jsonld-signatures');
const eproofs = require('equihash-signature');
eproofs.install(jsigs);
injector.use('jsonld-signatures', jsigs);

injector.env = {nodejs: true};

const VeresOne = require('./VeresOne');

module.exports = {
  injector,
  VeresOne,
  use: (name, injectable) => injector.use(name, injectable),
  veres: (options) => {
    return new VeresOne({injector, ...options});
  },
  VeresOneClient: require('./VeresOneClient'),
  VeresOneDidDoc: require('./VeresOneDidDoc')
};
