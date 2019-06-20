# did-veres-one ChangeLog

## 4.0.0 - TBD

### Changed
- **BREAKING**: Uses `v1.driver(options)` API instead of `v1.veres()`.
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
