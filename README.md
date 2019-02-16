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

### Generate a DID Document

Generate a new DID document.

* options - a set of options used when generating the DID Document
  * didType - the type of DID to generate.
      Options: 'nym' or 'uuid' (default: 'nym')
  * keyType - the type of keys to generate.
      Options: 'RsaVerificationKey2018' (default: 'RsaVerificationKey2018').
  * passphrase - the passphrase to use to encrypt the private keys for
      nym-based DIDs. Set to `null` if the private keys should not be encrypted.
  * mode - the mode/environment to generate the DID in.
      Options: 'dev', 'test', 'live' (default: 'dev').

Returns an object with:

* publicDidDocument - the generated DID Document.
* privateDidDocument - the DID Document augmented with the encrypted private
    keys in PEM format.

### Attach an ocap-ld delegation proof to a capability DID Document

Attach a Linked Data Object Capability Delegation proof to a DID Document that
is also a Linked Data Capability (Veres One DID Documents implicitly are). A
capability only requires a delegation proof if its `invocationTarget` is not
self-referencing. The delegation proof must be signed by a key referenced via
the `invocationTarget`'s `capabilityDelegation` relation.

* options - a set of options used when attaching the ocap-ld delegation proof
  * operation - the operation to attach the delegation proof to.
  * creator - the ID of the public key proving delegation authorization.
  * privateKeyPem - the private key material used to sign the proof.

Returns an operation object with an attached ocap-ld delegation proof.

### Wrap a DID Document in a Web Ledger Operation for submission to Veres One

Wrap a DID Document in a Web Ledger Operation. Once it is wrapped, it can
have Linked Data Capability invocation proofs attached to it and it can then
be submitted to Veres One to be stored on the ledger.

* options - a set of options used when wrapping the DID Document
  * didDocument - the DID Document to wrap.
  * operationType - the type of operation to wrap with.
      Options: 'create' will cause the operation type of `CreateWebLedgerRecord`
        to be used (default: 'create').

Returns an operation object ready to have proofs attached to it prior to
submission to a Veres One Accelerator or the Veres One ledger.

### Attach an ocap-ld invocation proof to an operation

Attach a Linked Data Object Capability Invocation proof to an operation. Once
the operation is submitted to Veres One, the ledger nodes will be able to
use the invocation proof to authorize the operation.

* options - a set of options used when attaching the ocap-ld invocation proof
  * operation - the operation to attach the invocation proof to.
  * capability - the ID of the capability that is being invoked (e.g. the
      ID of the record in the operation for self-invoked capabilities).
  * capabilityAction - the capability action being invoked.
  * creator - the ID of the public key proving invocation authorization.
  * privateKeyPem - the private key material used to sign the proof.

Returns an operation object with an attached ocap-ld invocation proof, ready to
be submitted to the Veres One ledger.
