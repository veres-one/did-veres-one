# did-veres-one ChangeLog

## 14.0.0 -

### `14.0.0-beta.1` - 2021-05-28

### Changed
- **BREAKING**: Change in `generate()` semantics to support the common un-registered
  DID use case. (See the "Upgrading from `<=12.x` section" below, item 1.)
  Now, `generate()` now only generates one key, for `capabilityInvocation` but 
  also all the other purposes (much like generating a new `did:key` DID).
  (Helper libraries are expected to generate other keys before registering the
  DID Document on the ledger.)

### `14.0.0-beta.0`

### Changed
- **BREAKING**: Update to the newest contexts, crypto suites, `did-io` version.
- **BREAKING**: Change `.generate()` return signature, now returns
  `{didDocument, keyPairs, methodFor}`.
- **BREAKING**: Remove unused/obsolete `passphrase` parameter.
- **BREAKING**: Remove the `forceConstruct` parameter from `.get()` --
  use the CachedResolver from https://github.com/digitalbazaar/did-io instead.
- **BREAKING**: Rename `.computeKeyId()` to `.computeId()`.

### Upgrading from <=12.x

**1)** DID Document `generate()` method return signature has changed.
Change in `generate()` semantics (as of `v14.0.0-beta.1`). Since we expect using 
an un-registered Veres One DID to be a common use case, the previous `generate()`
behavior introduced complications, since different keys for each proof purpose
were created by default. Except that, for the case of un-registered DIDs, the
next time it was resolved, the `capabilityInvocation` key was used (derived from
the cryptonym) as the signing key for all purposes (same behavior as `did:key`
DIDs). To simplify this, `generate()` now only generates one key, for
`capabilityInvocation` but also all the other purposes (much like generating
a new `did:key` DID). To support a proper diversity of keys for registered
DIDs, helper libraries are expected to generate and add additional keys for
other proof purposes, before registering a DID Document on the ledger.

**Before:** `const didDocument = await veresOneDriver.generate();`

The generated `didDocument` was an instance of the `VeresOneDidDoc` class,
and stored its own generated key pairs in `didDocument.keys`.
It also contained different keys for each proof purpose (they were generated,
if not explicitly provided).

**Now:** `const {didDocument, keyPairs, methodFor} = await veresOneDriver.generate();`

In v13, the generated `didDocument` is a plain Javascript object, with no
methods. Generated keys are returned in the `keyPairs` property (a js `Map`
instance, with key pairs stored by key id).
In addition, a helper method `methodFor` is provided, to help retrieve keys
for a particular purpose. For example:
`methodFor({purpose: 'capabilityInvocation'})` returns the first available
public/private key pair instance that is referenced in the DID Document's
`capabilityInvocation` verification relationship.

**2)** Driver `.get()` method has changed -- no longer uses the `forceConstruct`
parameter. Developers are encouraged to use the CachedResolver from 
https://github.com/digitalbazaar/did-io instead.
`driver.get()` can still be used to fetch either the full DID Document (via
`await driver.get({did})`) or a key document (via `await driver.get({url: keyId})`).

**3)** Check for `.computeKeyId()` usage. It's been renamed to `.computeId()`.

**4)** Validation methods have changed (used by the `did-veres-one` validator 
node):

- `didDocument.validateDid({mode})` becomes:
  `VeresOneDriver.validateDid({didDocument, mode})`
- `didDocument.validateMethodIds()` becomes:
  `VeresOneDriver.validateMethodIds({didDocument})`

## 13.0.2 - 2021-05-25

### Fixed
- Add more backwards compat for key pairs.

## 13.0.1 - 2021-04-21

### Fixed
- Add compatibility with newer ld-keypair `export()` api.

## 13.0.0 - 2021-03-12

### Changed
- **BREAKING**: Use `http-signature-header@2`. Includes breaking changes
  related to headers that contain timestamps.
- **BREAKING**: Drop support for Node.js 8.

## 12.2.0 - 2021-03-11

### Changed
- Use `apisauce@2` to address security vulnerabilities in the older `axios`
  sub-dependency.

## 12.1.1 - 2020-04-29

### Added
- Implement fetching of keys from un-registered cryptonym DIDs.

## 12.1.0 - 2020-04-13

### Added
- Added `computeKeyId()` and `method`, for use with `did-io` downstream.

## 12.0.0 - 2020-04-08

### Changed
- When retrieving an unregistered cryptonym-type DID via `get()` (and receiving
  a 404 from the ledger), fall back to creating a DID Doc deterministically
  from the cryptonym itself.

## 11.1.0 - 2020-04-02

### Changed
- Use ocapld@2.

## 11.0.1 - 2020-02-19

### Changed
- Fix tag version

## 11.0.0 - 2020-02-19

### Changed
- Fix dev-mode ledger endpoint.
- Update to Veres One Capybara testnet.

## 10.1.0 - 2020-02-14

### Changed
- Use jsonld-signatures@5.

## 10.0.1 - 2019-12-16

### Changed
- Fixed `didDocument.export()`.

## 10.0.0 - 2019-12-10

### Changed
- **BREAKING**: Updated contexts (
  `web-ledger-context@7`, `json-ld-patch-context@4`)
- Use jsonld@2.

## 9.1.1 - 2019-12-06

### Changed
- Fixed - do not use exported/encrypted key for `attachInvocationProof()`.

## 9.1.0 - 2019-12-05

### Added
- Implemented `rotateKey()`

### Changed
- Fixed setting of controllers for newly generated did doc keys.

## 9.0.0 - 2019-11-20

### Changed
- **BREAKING**: Updated contexts (`veres-one-context@11`,
  `web-ledger-context@6`, `veres-one-context@10`)

### Added
- Add `assertionMethod` proof purpose to generated DID Document

## 8.0.0 - 2019-10-15

### Changed
- **BREAKING**: Change `capabilityAction` values in invocation proofs.
  - `RegisterDid` is now `create`.
  - `UpdateDidDocument` is now `update`.
- **BREAKING**: Removed all APIs and tests related to Equihash.

## 7.1.0 - 2019-10-08

### Changed
- Update to dependencies with support for Node 12 native Ed25519 crypto.

## 7.0.0 - 2019-08-01

### Changed
- **BREAKING**: Uses `v1.driver(options)` API instead of `v1.veres()`.

## 6.0.0 - 2019-07-20

### Changed
- **BREAKING**: Default test hostname to `genesis.bee.veres.one`.

## 5.0.0 - 2019-06-19

This release is being made in support of Node.js command line tooling. A
browser compatible release will be made soon.

### Changed
- **BREAKING**: Numerous breaking API changes. See in-line jsdocs for changes.

## 4.0.0 - 2019-01-30

### Changed
- **BREAKING**: Use crypto-ld@3. crypto-ld@3 produces key fingerprints that
  have a different encoding from crypto-ld@2.
- **BREAKING**: Remove unnecessary `generateKeyObject` API.
- **BREAKING**: `validateKeyIds` has been renamed to `validateMethodIds`.
- **BREAKING**: `validateCryptonymDid` and `validateMethodIds` APIs now conform
  to validator convention and return `{valid: <boolean>, error: <Error>}`
  instead of throwing.
- **BREAKING**: `suiteForId` API has been renamed to
  `getAllVerificationMethods`.
- **BREAKING**: `suiteKeyNode` API has been renamed to `getVerificationMethod`
  with a new method signature.

## 3.0.0 - 2019-01-17

### Changed
- **BREAKING**: Replace "cryptographic suites" with flat verification methods
  like Ed25519VerificationKey2018.
- **BREAKING**: Removed injector usage, removed related `v1.use()` notation.
- Extracted VeresOne specific code from `did-io` into this lib.

## 2.0.0 - 2018-09-19

### Added
- Migrate to use multiformat for expression of cryptonym DIDs.
- Update ocap terminology.


## 1.0.0 - 2018-09-19

### Added
- Add `service` and `serviceEndpoint` terms.

### Changed
- Put service property in public did.
- Update ursa dependency to a Node 10.x compatible commit on #master.

## 0.1.2 - 2018-03-20

### Added
- Build browser file with webpack.

## 0.1.1 - 2018-03-20

### Added
- Add in-browser ed25519 key generation.

## 0.1.0 - 2018-03-20

### Added
- `publicDidDocument` to create a public DID document from a private document.

## 0.0.0 - 2018-02-24

- See git history for changes.
