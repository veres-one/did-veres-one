/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

module.exports = class VeresOneClientError extends Error {
  constructor(message, name, details) {
    super(message);
    this.name = name;
    this.details = details;
    Error.captureStackTrace(this, this.constructor);
  }
};
