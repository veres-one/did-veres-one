# Veres One DIDs

This library provides support classes for creating and processing
Decentralized Identifiers for Veres One. This library enables a developer to:

* Create a Veres One DID
* Generate Veres One cryptographic proofs

```
npm install did-veres-one
```

```js
const v1 = require('did-veres-one');

// See Configuration below for list of options
const options = {mode: 'dev', httpsAgent, hostname: 'localhost:12345'};
const veresDriver = v1.driver(options);
```

## Configuration

* options - a set of options used when generating the DID Document
  * didType - the type of DID to generate.
      Options: 'nym' or 'uuid' (default: 'nym')
  * `invokeKey` - optionally pass in a Capability Invocation key, otherwise
    it will be generated.
  * keyType - the type of keys to generate.
      Options: 'RsaVerificationKey2018' (default: 'RsaVerificationKey2018').
  * hostname - ledger node hostname override
  * passphrase - the passphrase to use to encrypt the private keys for
      nym-based DIDs. Set to `null` if the private keys should not be encrypted.
  * mode - the mode/environment to generate the DID in.
      Options: 'dev', 'test', 'live' (default: 'dev').

If you do not specify a particular ledger hostname, one will be determined
based on the `mode` parameter (either 'test', 'dev' or 'live').

If you want to connect to a specific hostname (for testing a particular node,
for example), you can specify the override directly:

## API Documentation

The API documentation provided below is for the Promises-based API. The
callback API works the same way where the callback provides the value for the
resolved Promise.

### Generate a DID Document

#### Generating and Registering a Veres One DID Document

```js
// Generate a new DID Document, store the private keys locally
veresDriver
  .generate({didType: 'nym', keyType: 'Ed25519VerificationKey2018'}) // default
  .then(didDocument => {
    // A new didDocument is generated. Log it to console
    console.log('Generated:', JSON.stringify(didDocument, null, 2));
    return didDocument;
  })

  // Now register the newly generated DID Document
  .then(didDocument => veresDriver.register({ didDocument }))

  // Log the results
  .then(registrationResult => {
    // Log the result of registering the didDoc to the VeresOne Test ledger
    console.log('Registered!', JSON.stringify(registrationResult, null, 2));
  })
  .catch(console.error);
```

#### Registering a (newly generated) DID Document

To register a DID Document using an Equihash proof of work:

```js
veresDriver.register({ didDocument }).then().catch();
```

To register using an Accelerator:

```js
const accelerator = 'genesis.testnet.veres.one';
const authDoc = didDocumentFromAccelerator; // obtained previously

veresDriver.register({ didDocument, accelerator, authDoc })
  .then(result => console.log(JSON.stringify(await result.text(), null, 2)))
  .catch(console.error);
```

#### `get()` - Retrieving a Veres One DID Document

```js
const did = 'did:v1:test:nym:ApvL3PKAzQvFnRVqyZKhSYD2i8XcsLG1Dy4FrSdEKAdR';

veresDriver.get({ did })
  .then(didDoc => { console.log(JSON.stringify(didDoc, null, 2)); })
  .catch(console.error);
```

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
