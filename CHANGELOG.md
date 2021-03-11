# did-veres-one ChangeLog

## 12.2.0 -2021-03-11

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
