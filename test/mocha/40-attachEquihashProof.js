/*
 * Copyright (c) 2018 Veres One Project. All rights reserved.
 */
/* global should */
'use strict';

const expect = global.chai.expect;

describe('Veres One attachEquihashProof', () => {
  const didv1 = require('../../lib');

  // FIXME: determine how to simplify/move this code out of test
  const jsonld = didv1.use('jsonld');
  const documentLoader = jsonld.documentLoader;
  jsonld.documentLoader = async url => {
    if(url in didv1.contexts) {
      return {
        contextUrl: null,
        documentUrl: url,
        document: didv1.contexts[url]
      };
    }
    return documentLoader(url);
  };
  const jsigs = require('jsonld-signatures');
  jsigs.use('jsonld', jsonld);
  didv1.use('jsonld-signatures', jsigs);
  const eproofs = require('equihash-signature');
  eproofs.use('jsonld', jsonld);

  it('should attach an equihash proof to an operation', async () => {
    // generate a DID Document
    const {publicDidDocument: didDocument, privateDidDocument} =
      await didv1.generate({passphrase: null});

    // attach an capability invocation proof
    let operation = didv1.wrap({didDocument});
    const creator = didDocument.invokeCapability[0].publicKey.id;
    const privateKeyPem = privateDidDocument.invokeCapability[0].publicKey
      .privateKeyPem;

    operation = await didv1.attachInvocationProof({
      operation,
      capability: didDocument.id,
      capabilityAction: operation.type,
      creator,
      privateKeyPem
    });

    // attach an equihash proof
    operation = await didv1.attachEquihashProof({operation});

    expect(operation.type).to.equal('CreateWebLedgerRecord');
    expect(operation.record.id).to.match(/^did\:v1\:test\:nym\:.*/);
    expect(operation.record.authentication[0].publicKey.publicKeyPem)
      .to.have.string('-----BEGIN PUBLIC KEY-----');
    expect(operation.proof).to.exist;
    // capability invocation proof
    expect(operation.proof).to.exist;
    expect(operation.proof.type).to.equal('RsaSignature2018');
    expect(operation.proof.capabilityAction).to.equal(operation.type);
    expect(operation.proof.proofPurpose).to.equal('invokeCapability');
    expect(operation.proof.creator).to.equal(creator);
    expect(operation.proof.jws).to.exist;
    // equihash proof
    // FIXME: convert to `proof`
    expect(operation.signature).to.exist;
    expect(operation.signature.type).to.equal('EquihashProof2017');
    expect(operation.signature.equihashParameterN).to.exist;
    expect(operation.signature.equihashParameterK).to.exist;
    expect(operation.signature.nonce).to.exist;
    // FIXME: change to `solution`?
    expect(operation.signature.proofValue).to.exist;

    // // capability invocation proof
    // expect(operation.proof[0]).to.exist;
    // expect(operation.proof[0].type).to.equal('RsaSignature2018');
    // expect(operation.proof[0].capabilityAction).to.equal(operation.type);
    // expect(operation.proof[0].proofPurpose).to.equal('invokeCapability');
    // expect(operation.proof[0].creator).to.equal(creator);
    // expect(operation.proof[0].jws).to.exist;
    // // equihash proof
    // expect(operation.proof[1]).to.exist;
    // expect(operation.proof[1].type).to.equal('EquihashProof2017');
    // expect(operation.proof[1].equihashParameterN).to.exist;
    // expect(operation.proof[1].equihashParameterK).to.exist;
    // expect(operation.proof[1].nonce).to.exist;
    // expect(operation.proof[1].solution).to.exist;
  }).timeout(30000);

});
