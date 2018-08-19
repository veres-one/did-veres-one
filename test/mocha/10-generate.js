/*
 * Copyright (c) 2018 Veres One Project. All rights reserved.
 */
/* global should */
'use strict';

const expect = global.chai.expect;

describe('Veres One generate DIDs', () => {
  const didv1 = require('../../lib');

  it('should generate protected RSA nym-based DID Document', async () => {
    const nymOptions = {
      keyType: 'RsaVerificationKey2018',
      passphrase: 'foobar'
    };
    const didDocument = await didv1.generate(nymOptions);

    expect(didDocument.publicDidDocument.id).to.match(
      /^did\:v1\:test\:nym\:.*/);
    expect(
      didDocument.publicDidDocument.authentication[0].publicKey[0].publicKeyPem)
      .to.have.string('-----BEGIN PUBLIC KEY-----');
    expect(
      didDocument.privateDidDocument.authentication[0].publicKey[0]
        .privateKey.privateKeyPem)
      .to.have.string('-----BEGIN ENCRYPTED PRIVATE KEY-----');
  }).timeout(30000);

  it('should generate unprotected RSA nym-based DID Document', async () => {
    const nymOptions = {
      keyType: 'RsaVerificationKey2018',
      passphrase: null
    };
    const didDocument = await didv1.generate(nymOptions);

    expect(didDocument.publicDidDocument.id).to.match(
      /^did\:v1\:test\:nym\:.*/);
    expect(
      didDocument.publicDidDocument.authentication[0].publicKey[0].publicKeyPem)
      .to.have.string('-----BEGIN PUBLIC KEY-----');
    expect(
      didDocument.privateDidDocument.authentication[0].publicKey[0]
        .privateKey.privateKeyPem)
      .to.have.string('-----BEGIN RSA PRIVATE KEY-----');
  }).timeout(30000);

  it('should generate protected ed25519 nym-based DID Document', async () => {
    const nymOptions = {
      keyType: 'Ed25519VerificationKey2018',
      passphrase: 'foobar'
    };
    const didDocument = await didv1.generate(nymOptions);

    expect(didDocument.publicDidDocument.id).to.match(
      /^did\:v1\:test\:nym\:z.*/);
    expect(didDocument.privateDidDocument.authentication[0].publicKey[0].id)
      .to.have.string('nym:z');
    expect(didDocument.privateDidDocument.authentication[0].publicKey[0]
      .privateKey.jwe.ciphertext)
      .to.have.lengthOf.above(128);
    expect(didDocument.publicDidDocument.authentication[0].publicKey[0]
      .publicKeyBase58)
      .to.have.lengthOf(44);
  }).timeout(30000);

  it('should generate unprotected ed25519 nym-based DID Document', async () => {
    const nymOptions = {
      keyType: 'Ed25519VerificationKey2018',
      passphrase: null
    };
    const didDocument = await didv1.generate(nymOptions);

    expect(didDocument.publicDidDocument.id).to.match(
      /^did\:v1\:test\:nym\:z.*/);
    expect(didDocument.privateDidDocument.authentication[0].publicKey[0].id)
      .to.have.string('nym:z');
    expect(didDocument.publicDidDocument.authentication[0].publicKey[0]
      .publicKeyBase58)
      .to.have.lengthOf(44);
  }).timeout(30000);

  it('should generate uuid-based DID Document', async () => {
    const uuidOptions = {
      didType: 'uuid'
    };
    const didDocument = await didv1.generate(uuidOptions);

    expect(didDocument.publicDidDocument.id).to.match(
      /^did\:v1\:test\:uuid\:.*/);
  });

});
