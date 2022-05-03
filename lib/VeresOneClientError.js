/*!
 * Copyright (c) 2018-2022 Veres One Project. All rights reserved.
 */
export class VeresOneClientError extends Error {
  constructor(message, name, details) {
    super(message);
    this.name = name;
    this.details = details;
    Error.captureStackTrace(this, this.constructor);
  }
}
