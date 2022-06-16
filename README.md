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

| Network | Client library version |
| :--- | :--- |
| Capybara Testnet | ^13.0.0 |
| Local ledger dev/testing | ^14.0.0, ^15.0.0 |

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

- Browsers and Node.js 14+ are supported.

To install from NPM:

```
npm install did-veres-one
```

```js
import * as v1 from 'did-veres-one';
// or
const v1 = require('did-veres-one');

// See Configuration below for list of options

const veresDriver = v1.driver(options);
```

### Generate a Veres One DID Document

```js
// Generate a new DID Document
const didDocument = await veresDriver.generate(); // default

// A DID Document can also be generated from a 32-byte array seed
const didDocument = await veresDriver.generate({seed});

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
  "id": "did:v1:nym:z6MkqgytJzVovDLiinRZRm3UcxX5z7XETCQLVMgcugWaNuPe",
  "capabilityInvocation": [{
    "id": "did:v1:nym:z6MkqgytJzVovDLiinRZRm3UcxX5z7XETCQLVMgcugWaNuPe#z6MkqgytJzVovDLiinRZRm3UcxX5z7XETCQLVMgcugWaNuPe",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:v1:nym:z6MkqgytJzVovDLiinRZRm3UcxX5z7XETCQLVMgcugWaNuPe",
    "publicKeyMultibase": "zCEiqikFNafrFcHarkC5dmry6AYFP3K9yoLmh5QYZTgcG"
  }],
  "authentication": [
    "did:v1:nym:z6MkqgytJzVovDLiinRZRm3UcxX5z7XETCQLVMgcugWaNuPe#z6MkqgytJzVovDLiinRZRm3UcxX5z7XETCQLVMgcugWaNuPe"
  ],
  "assertionMethod": [
    "did:v1:nym:z6MkqgytJzVovDLiinRZRm3UcxX5z7XETCQLVMgcugWaNuPe#z6MkqgytJzVovDLiinRZRm3UcxX5z7XETCQLVMgcugWaNuPe"
  ],
  "capabilityDelegation": [
    "did:v1:nym:z6MkqgytJzVovDLiinRZRm3UcxX5z7XETCQLVMgcugWaNuPe#z6MkqgytJzVovDLiinRZRm3UcxX5z7XETCQLVMgcugWaNuPe"
  ],
  "keyAgreement": [{
    "id": "did:v1:nym:z6MkqgytJzVovDLiinRZRm3UcxX5z7XETCQLVMgcugWaNuPe#z6LSjgGK5fg5wxns7d16g1QJHweYEVrDgNoVPncf2Wg85V2S",
    "type": "X25519KeyAgreementKey2020",
    "controller": "did:v1:nym:z6MkqgytJzVovDLiinRZRm3UcxX5z7XETCQLVMgcugWaNuPe",
    "publicKeyMultibase": "z9169ZMsDrW582EdL9MtLyMS4PMK6ymdLWotyY42bN7Fg"
  }]
}
```

#### Backwards Compatibility with the 2018/2019 Crypto Suites

By default, this `did:v1` driver returns DID Documents that have the 2020
crypto suites for verification and key agreement.
If you need DID Documents that are using the 2018/2019 crypto suites,
you can customize the driver as follows.

```js
import {
  Ed25519VerificationKey2018
} from '@digitalbazaar/ed25519-verification-key-2018';
import * as v1 from 'did-veres-one';
import {CryptoLD} from 'crypto-ld';

const cryptoLd = new CryptoLD();
cryptoLd.use(Ed25519VerificationKey2018);

const veresOneDriver2018 = v1.driver({
 cryptoLd, verificationSuite: Ed25519VerificationKey2018
});

await veresOneDriver2018.generate();
// ->
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/veres-one/v1",
    "https://w3id.org/security/suites/ed25519-2018/v1",
    "https://w3id.org/security/suites/x25519-2019/v1"
  ],
    "id": "did:v1:nym:z6MkwTeb9YkCk8axegydVDTQj271wxEMRjAkfF6pFexrFbJz",
    "capabilityInvocation": [{
      "id": "did:v1:nym:z6MkwTeb9YkCk8axegydVDTQj271wxEMRjAkfF6pFexrFbJz#z6MkwTeb9YkCk8axegydVDTQj271wxEMRjAkfF6pFexrFbJz",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:nym:z6MkwTeb9YkCk8axegydVDTQj271wxEMRjAkfF6pFexrFbJz",
      "publicKeyBase58": "J1PYZJVmQb6VYC8voeVZsvZ28NxW1qvPyEBtRNzqLNXc"
    }],
    "authentication": [
      "did:v1:nym:z6MkwTeb9YkCk8axegydVDTQj271wxEMRjAkfF6pFexrFbJz#z6MkwTeb9YkCk8axegydVDTQj271wxEMRjAkfF6pFexrFbJz"
    ],
    "assertionMethod": [
      "did:v1:nym:z6MkwTeb9YkCk8axegydVDTQj271wxEMRjAkfF6pFexrFbJz#z6MkwTeb9YkCk8axegydVDTQj271wxEMRjAkfF6pFexrFbJz"
    ],
    "capabilityDelegation": [
      "did:v1:nym:z6MkwTeb9YkCk8axegydVDTQj271wxEMRjAkfF6pFexrFbJz#z6MkwTeb9YkCk8axegydVDTQj271wxEMRjAkfF6pFexrFbJz"
    ],
    "keyAgreement": [{
      "id": "did:v1:nym:z6MkwTeb9YkCk8axegydVDTQj271wxEMRjAkfF6pFexrFbJz#z6LSjVA39Bmi8hNYt8ySM36fhurdpFTsCudVZTvUWAa8XKvt",
      "type": "X25519KeyAgreementKey2019",
      "controller": "did:v1:nym:z6MkwTeb9YkCk8axegydVDTQj271wxEMRjAkfF6pFexrFbJz",
      "publicKeyBase58": "8oyscsxr3EeonkbfpPaiPKe9y6vkWJTLgVCo1hvboxA8"
  }]
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
