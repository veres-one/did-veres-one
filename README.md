# Veres One DID Driver (_did-veres-one_)

[![Build Status](https://travis-ci.org/veres-one/did-veres-one.svg?branch=master&style=flat-square)](https://travis-ci.org/veres-one/did-veres-one)
[![NPM Version](https://img.shields.io/npm/v/did-veres-one.svg?style=flat-square)](https://npm.im/did-veres-one)

## Background

This library provides support classes for creating and processing
Decentralized Identifiers for [Veres One](https://veres.one/). This library
enables a developer to:

* Create a Veres One DID
* Generate Veres One cryptographic proofs

### Compatibility

* **`^v13.0.0`** - Compatible with the current Capybara testnet.
* `^v14.0.0` - bleeding edge, not compatible with testnet.

## Configuration

* `options` - a set of options used when generating the DID Document
  * `didType` - the type of DID to generate.
      Options: `'nym'` (default) or `'uuid'`
  * `invokeKey` - optionally pass in a Capability Invocation key, otherwise
    it will be generated.
  * `keyType` - the type of keys to generate.
      Options: `'Ed25519VerificationKey2020'` (default)
  * `hostname` - ledger node hostname override
  * `mode` - the mode/environment to generate the DID in.
      Options: `'dev'` (default), `'test'`, `'live'`

If you do not specify a particular ledger hostname, one will be automatically
selected based on the `mode` parameter (either 'test', 'dev' or 'live').

If you want to connect to a specific hostname (for testing a particular node,
for example), you can specify the override directly:

## Usage

### Installation

```
npm install did-veres-one
```

```js
const v1 = require('did-veres-one');

// See Configuration below for list of options
const options = {mode: 'dev', httpsAgent, hostname: 'localhost:12345'};
const veresDriver = v1.driver(options);
```

### Generate a Veres One DID Document

```js
// Generate a new DID Document
const didDocument = await veresDriver.generate(
  {didType: 'nym', keyType: 'Ed25519VerificationKey2018'}); // default

// Log the new didDocument to the console.
console.log(JSON.stringify(didDocument, null, 2));
```

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/veres-one/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://w3id.org/security/suites/x25519-2020/v1"
  ],
  "id": "did:v1:test:nym:z6Mkkqz5hWq2vT3un8UWLhXEDBHLbUpaWM2yvZRpAPkU25qg",
  "authentication": [
    {
      "id": "did:v1:test:nym:z6Mkkqz5hWq2vT3un8UWLhXEDBHLbUpaWM2yvZRpAPkU25qg#z6MknK4SCXDjgBh5gnduDraF7TtTpxqzR4yL3VvF6V9TnRs8",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:v1:test:nym:z6Mkkqz5hWq2vT3un8UWLhXEDBHLbUpaWM2yvZRpAPkU25qg",
      "publicKeyMultibase": "z8roPcGyJLeCcaHoCYHcQGNLU1Pa91BiyMV1KGDBSsD5k"
    }
  ],
  "assertionMethod": [
    {
      "id": "did:v1:test:nym:z6Mkkqz5hWq2vT3un8UWLhXEDBHLbUpaWM2yvZRpAPkU25qg#z6MknM5XL4EFGQ2WXypE1hb1SusqikD352UhKL8YANYhNDnQ",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:v1:test:nym:z6Mkkqz5hWq2vT3un8UWLhXEDBHLbUpaWM2yvZRpAPkU25qg",
      "publicKeyMultibase": "z8tpUjoyovrY3RUyXL8dAbpKquAwBf9ELdKDcL6agT112"
    }
  ],
  "capabilityDelegation": [
    {
      "id": "did:v1:test:nym:z6Mkkqz5hWq2vT3un8UWLhXEDBHLbUpaWM2yvZRpAPkU25qg#z6Mknt9TWRoN86Kq2pcPoWa6PaqfUMrVDcNRgTn9y1R984V3",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:v1:test:nym:z6Mkkqz5hWq2vT3un8UWLhXEDBHLbUpaWM2yvZRpAPkU25qg",
      "publicKeyMultibase": "z9RtQvBYvnYqMvKmh7wcFYVHfenadoj84zSsE8jT8Cqhf"
    }
  ],
  "capabilityInvocation": [
    {
      "id": "did:v1:test:nym:z6Mkkqz5hWq2vT3un8UWLhXEDBHLbUpaWM2yvZRpAPkU25qg#z6Mkkqz5hWq2vT3un8UWLhXEDBHLbUpaWM2yvZRpAPkU25qg",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:v1:test:nym:z6Mkkqz5hWq2vT3un8UWLhXEDBHLbUpaWM2yvZRpAPkU25qg",
      "publicKeyMultibase": "z7Pj37GabauZSfddof8ZPN5jLmuYj6TndEYWtL7nT6s4J"
    }
  ],
  "keyAgreement": [
    {
      "id": "did:v1:test:nym:z6Mkkqz5hWq2vT3un8UWLhXEDBHLbUpaWM2yvZRpAPkU25qg#z6LSedETAHzL3UAvsenNoFxvjhyzM4jmppN5SWNMWFNFJtdY",
      "type": "X25519KeyAgreementKey2020",
      "controller": "did:v1:test:nym:z6Mkkqz5hWq2vT3un8UWLhXEDBHLbUpaWM2yvZRpAPkU25qg",
      "publicKeyMultibase": "z3x4HdzBTx1TBnGQcGcSyR7mWVvCf8DBvZXeg1niibWrn"
    }
  ]
}
```

### Register a DID Document

To register a DID Document (after it's generated):

```js
const registrationResult = await veresDriver.register({didDocument});

// Log the result of registering the didDoc to the VeresOne Test ledger
console.log('Registered!', JSON.stringify(registrationResult, null, 2));
```

### Retrieve a Registered Veres One DID Document

If a DID is registered on the ledger, a `get()` operation will retrieve it:

```js
const did = 'did:v1:test:nym:z6Mkkqz5hWq2vT3un8UWLhXEDBHLbUpaWM2yvZRpAPkU25qg';
const didDoc = await veresDriver.get({did});
console.log(JSON.stringify(didDoc, null, 2));
```

```js
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/veres-one/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://w3id.org/security/suites/x25519-2020/v1"
  ],
    "id": "did:v1:test:nym:z6Mkkqz5hWq2vT3un8UWLhXEDBHLbUpaWM2yvZRpAPkU25qg",
  // ... etc
}
```

### Retrieve an Unregistered Veres One DID Document

If a DID is _not_ registered on the ledger, and it's of a cryptonym type
(that is, `did:v1:nym:` or `did:v1:test:nym:`), it will be deterministically
constructed from the public key (which is encoded in the cryptonym DID itself).

```js
const did = 'did:v1:test:nym:z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt';
const didDoc = await veresDriver.get({did});
console.log(JSON.stringify(didDoc, null, 2));
```

### Attach an OCAP-LD delegation proof to a capability DID Document

Attach a Linked Data Object Capability Delegation proof to a DID Document that
is also a Linked Data Capability (Veres One DID Documents implicitly are). A
capability only requires a delegation proof if its `invocationTarget` is not
self-referencing. The delegation proof must be signed by a key referenced via
the `invocationTarget`'s `capabilityDelegation` relation.

* `options` - a set of options used when attaching the ocap-ld delegation proof
  * `operation` - the operation to attach the delegation proof to.
  * `creator` - the ID of the public key proving delegation authorization.
  * `privateKeyPem` - the private key material used to sign the proof.

Returns an operation object with an attached ocap-ld delegation proof.

### Wrap a DID Document in a Web Ledger Operation for submission to Veres One

Wrap a DID Document in a Web Ledger Operation. Once it is wrapped, it can
have Linked Data Capability invocation proofs attached to it and it can then
be submitted to Veres One to be stored on the ledger.

* `options` - a set of options used when wrapping the DID Document
  * `didDocument` - the DID Document to wrap.
  * `operationType` - the type of operation to wrap with.
      Options: 'create' will cause the operation type of `CreateWebLedgerRecord`
        to be used (default: 'create').

Returns an operation object ready to have proofs attached to it prior to
submission to a Veres One Accelerator or the Veres One ledger.

### Attach an OCAP-LD invocation proof to an operation

Attach a Linked Data Object Capability Invocation proof to an operation. Once
the operation is submitted to Veres One, the ledger nodes will be able to
use the invocation proof to authorize the operation.

* `options` - a set of options used when attaching the ocap-ld invocation proof
  * `operation` - the operation to attach the invocation proof to.
  * `capability` - the ID of the capability that is being invoked (e.g. the
      ID of the record in the operation for self-invoked capabilities).
  * `capabilityAction` - the capability action being invoked.
  * `creator` - the ID of the public key proving invocation authorization.
  * `privateKeyPem` - the private key material used to sign the proof.

Returns an operation object with an attached ocap-ld invocation proof, ready to
be submitted to the Veres One ledger.
