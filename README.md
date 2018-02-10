# Veres One DIDs

This library provides support classes for creating and processing
Decentralized Identifiers for Veres One. This library enables a developer to:

* Create a Veres One DID
* Perform Veres One key rotation
* Generate Veres One cryptographic proofs

## The Promises API

  * api.generate(options)

## The Callback API (node.js)

  * api.generate(options, (err, didDocument))

## Quick Examples

```
npm install did-veres-one
```

```js
const didv1 = require('did-veres-one');
const options = {};

// generate the DID document
const didDocument = await didv1.generate();
```

## Configuration

For documentation on configuration, see [config.js](./lib/config.js).

## API Documentation

The API documentation provided below is for the Promises-based API. The
callback API works the same way where the callback provides the value for the
resolved Promise.

### Generating a DID Document

Generate a new DID document.

* options - a set of options used when generating the DID Document
  * didType - the type of DID to generate.
      Options: 'nym' or 'uuid' (default: 'nym')
  * keyType - the type of keys to generate.
      Options: 'RsaSigningKey2018' (default: 'RsaSigningKey2018')
  * passphrase - the passphrase to use to encrypt the private keys for
      nym-based DIDs. Set to `null` if the private keys should not be encrypted.

An object containing the public DID Document and a DID Document containing
the encrypted private keys.
