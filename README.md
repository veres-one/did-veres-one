# Veres One DID Driver (_did-veres-one_)

[![Build Status](https://travis-ci.org/veres-one/did-veres-one.svg?branch=master&style=flat-square)](https://travis-ci.org/veres-one/did-veres-one)
[![NPM Version](https://img.shields.io/npm/v/did-veres-one.svg?style=flat-square)](https://npm.im/did-veres-one)

This library provides support classes for creating and processing
Decentralized Identifiers for [Veres One](https://veres.one/). This library
enables a developer to:

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

* `options` - a set of options used when generating the DID Document
  * `didType` - the type of DID to generate.
      Options: 'nym' (default) or 'uuid'
  * `invokeKey` - optionally pass in a Capability Invocation key, otherwise
    it will be generated.
  * `keyType` - the type of keys to generate.
      Options: 'Ed25519VerificationKey2018' (default)
  * `hostname` - ledger node hostname override
  * `passphrase` - the passphrase to use to encrypt the private keys for
      nym-based DIDs. Set to `null` if the private keys should not be encrypted.
  * `mode` - the mode/environment to generate the DID in.
      Options: 'dev' (default), 'test', 'live'

If you do not specify a particular ledger hostname, one will be automatically
selected based on the `mode` parameter (either 'test', 'dev' or 'live').

If you want to connect to a specific hostname (for testing a particular node,
for example), you can specify the override directly:

## Usage

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
    "https://w3id.org/did/v0.11",
    "https://w3id.org/veres-one/v1"
  ],
  "id": "did:v1:nym:z6MksFxi8wnHkNq4zgEskSZF45SuWQ4HndWSAVYRRGe9qDks",
  "authentication": [
    {
      "id": "did:v1:nym:z6MksFxi8wnHkNq4zgEskSZF45SuWQ4HndWSAVYRRGe9qDks#z6MkhVG8DoVv7C613wFJKeG3kz2Z6cR2EShQexgctTSjdmSg",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:nym:z6MksFxi8wnHkNq4zgEskSZF45SuWQ4HndWSAVYRRGe9qDks",
      "publicKeyBase58": "4315dZFUmebXwSQbe5JCutUZH39ApZT3xwmh4BUiiYfJ"
    }
  ],
  "capabilityInvocation": [
    {
      "id": "did:v1:nym:z6MksFxi8wnHkNq4zgEskSZF45SuWQ4HndWSAVYRRGe9qDks#z6MksFxi8wnHkNq4zgEskSZF45SuWQ4HndWSAVYRRGe9qDks",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:nym:z6MksFxi8wnHkNq4zgEskSZF45SuWQ4HndWSAVYRRGe9qDks",
      "publicKeyBase58": "DohfYhXrQqLbtBQB4sbQCytugpnSNkG5UUdVazg8uzyV"
    }
  ],
  "capabilityDelegation": [
    {
      "id": "did:v1:nym:z6MksFxi8wnHkNq4zgEskSZF45SuWQ4HndWSAVYRRGe9qDks#z6MkhiwG4o9Etzy9DSNgbLY8rp6k73gKXtxrLBA7YdMxCAUZ",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:nym:z6MksFxi8wnHkNq4zgEskSZF45SuWQ4HndWSAVYRRGe9qDks",
      "publicKeyBase58": "4GgDUYtoZTUg6wXyumaJ1iYkHUQU81iVeAFBiMPwGwhB"
    }
  ],
  "assertionMethod": [
    {
      "id": "did:v1:nym:z6MksFxi8wnHkNq4zgEskSZF45SuWQ4HndWSAVYRRGe9qDks#z6MkqCDK1yGQxTbwDF7TkJhYeycPW35rPjAkMQGp8weGQPhz",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:nym:z6MksFxi8wnHkNq4zgEskSZF45SuWQ4HndWSAVYRRGe9qDks",
      "publicKeyBase58": "BjxGRj1ycv7U6kGm4jjhot4PgTozyqvPfPMtJfgFVAvc"
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
const did = 'did:v1:test:nym:z6Mkmpe2DyE4NsDiAb58d75hpi1BjqbH6wYMschUkjWDEEuR';
const didDoc = await veresDriver.get({did});
console.log(JSON.stringify(didDoc, null, 2));
```

```json
{
  "@context": [
    "https://w3id.org/did/v0.11",
    "https://w3id.org/veres-one/v1"
  ],
  "id": "did:v1:test:nym:z6Mkmpe2DyE4NsDiAb58d75hpi1BjqbH6wYMschUkjWDEEuR",
  "authentication": [
    {
      "id": "did:v1:test:nym:z6Mkmpe2DyE4NsDiAb58d75hpi1BjqbH6wYMschUkjWDEEuR#z6Mkf819vudPCgWPd1BX9objVMPz9XHDNwCwJb4R44vXbnd8",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:z6Mkmpe2DyE4NsDiAb58d75hpi1BjqbH6wYMschUkjWDEEuR",
      "publicKeyBase58": "fk7LfNws91vWWLpUEdteFqzKx1My3xaca9VDnxWgZqk"
    }
  ],
  "capabilityInvocation": [
    {
      "id": "did:v1:test:nym:z6Mkmpe2DyE4NsDiAb58d75hpi1BjqbH6wYMschUkjWDEEuR#z6Mkmpe2DyE4NsDiAb58d75hpi1BjqbH6wYMschUkjWDEEuR",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:z6Mkmpe2DyE4NsDiAb58d75hpi1BjqbH6wYMschUkjWDEEuR",
      "publicKeyBase58": "8NNydiyd3KjF46ERwY7rycTBvGKRh4J1BbnYvTYCK283"
    }
  ],
  "capabilityDelegation": [
    {
      "id": "did:v1:test:nym:z6Mkmpe2DyE4NsDiAb58d75hpi1BjqbH6wYMschUkjWDEEuR#z6Mkt5qQB4193KBYrHJjCUgS243LfCiHJLsrdRNPngGNngao",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:z6Mkmpe2DyE4NsDiAb58d75hpi1BjqbH6wYMschUkjWDEEuR",
      "publicKeyBase58": "EdaMaokhhmh5jnU2WuibAxVLqdSRtTdVwQTTxQJMsToR"
    }
  ],
  "assertionMethod": [
    {
      "id": "did:v1:test:nym:z6Mkmpe2DyE4NsDiAb58d75hpi1BjqbH6wYMschUkjWDEEuR#z6MkkdPW8kjhZXRM73aTzyuw5fEd5CYAFmuAk8dJN91Y34XG",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:z6Mkmpe2DyE4NsDiAb58d75hpi1BjqbH6wYMschUkjWDEEuR",
      "publicKeyBase58": "7B8TYWVGDyvszYjmKQx6EZgdFdGJqtep47iNXs3X7qjt"
    }
  ]
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

```json
{
  "@context": [
    "https://w3id.org/did/v0.11",
    "https://w3id.org/veres-one/v1"
  ],
  "id": "did:v1:test:nym:z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt",
  "authentication": [
    {
      "id": "did:v1:test:nym:z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt#z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt",
      "publicKeyBase58": "QugeAcHQwASabUMTXFNefYdBeD8wU24CENyayNzkXuW"
    }
  ],
  "capabilityInvocation": [
    {
      "id": "did:v1:test:nym:z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt#z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt",
      "publicKeyBase58": "QugeAcHQwASabUMTXFNefYdBeD8wU24CENyayNzkXuW"
    }
  ],
  "capabilityDelegation": [
    {
      "id": "did:v1:test:nym:z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt#z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt",
      "publicKeyBase58": "QugeAcHQwASabUMTXFNefYdBeD8wU24CENyayNzkXuW"
    }
  ],
  "assertionMethod": [
    {
      "id": "did:v1:test:nym:z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt#z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:v1:test:nym:z6MkesAjEQrikUeuh6K496DDVm6d1DUzMMGQtFHuRFM1fkgt",
      "publicKeyBase58": "QugeAcHQwASabUMTXFNefYdBeD8wU24CENyayNzkXuW"
    }
  ]
}
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
