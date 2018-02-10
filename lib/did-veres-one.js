/*
 * Copyright (c) 2018 Veres One Project. All rights reserved.
 */
(function(global) {

'use strict';

const Injector = require('./Injector');
const util = require('./util');

// determine if using node.js or browser
const _nodejs = (
  typeof process !== 'undefined' && process.versions && process.versions.node);
const _browser = !_nodejs &&
  (typeof window !== 'undefined' || typeof self !== 'undefined');

/**
 * Attaches the JSON-LD Signatures API to the given object.
 *
 * @param api the object to attach the signatures API to.
 * @param [options] the options to use:
 *          [inject] *deprecated*, use `use` API instead; the dependencies to
 *              inject, available global defaults will be used otherwise.
 *            [forge] forge API.
 *            [jsonld] jsonld.js API; all remote documents will be loaded
 *              using jsonld.documentLoader by default, so ensure a secure
 *              document loader is configured.
 */
function wrap(api, options) {

options = options || {};

const injector = new Injector();

/* Core API */

/**
 * Generate a new DID Document.
 */
api.generate = util.callbackify(async function(options) {
  options = options || {};
  const didType = options.didType || 'nym';
  const keyType = options.keyType || 'RsaSigningKey2018'
  const publicDidDocument = {
    '@context': 'https://w3id.org/veres-one/v1',
  };
  let privateDidDocument = null;

  // passphrase is a required parameter if generating a nym-based DID
  if(didType === 'nym' && !('passphrase' in options)) {
    throw new TypeError('"options.passphrase" must be specified.');
  }

  if(didType === 'nym') {
    // generate the nym-based DID
    const forge = injector.use('forge');
    const keyBits = (keyType === 'rsaSigningKey2018') ? 2048 : 2048;

    // generate keypairs
    const authenticationKeys = forge.pki.rsa.generateKeyPair(keyBits);
    const grantCapabilityKeys = forge.pki.rsa.generateKeyPair(keyBits);
    const invokeCapabilityKeys = forge.pki.rsa.generateKeyPair(keyBits);

    // generate nym
    const fingerprintBuffer = forge.pki.getPublicKeyFingerprint(
      authenticationKeys.publicKey, {
      md: forge.md.sha256.create()
    });
    const did = 'did:v1:nym:' + util.encodeBase64Url(
      fingerprintBuffer.bytes(), {forge});

    publicDidDocument.id = did;
    publicDidDocument.authentication = [{
      type: 'RsaSignatureAuthentication2018',
      publicKey: {
        // this key can be used to authenticate as DID entity
        id: did + '#authn-key-1',
        type: 'RsaSigningKey2018',
        owner: did,
        publicKeyPem: forge.pki.publicKeyToPem(authenticationKeys.publicKey)
      }
    }];

    publicDidDocument.grantCapability = [{
      type: 'RsaSignatureCapabilityAuthorization2018',
      publicKey: {
        // this key can be used to grant capabilities as DID entity
        id: did + '#ocap-grant-key-1',
        type: 'RsaSigningKey2018',
        owner: did,
        publicKeyPem: forge.pki.publicKeyToPem(grantCapabilityKeys.publicKey)
      }
    }];

    publicDidDocument.invokeCapability = [{
      type: 'RsaSignatureCapabilityAuthorization2018',
      publicKey: {
        // this key can be used to invoke capabilities as DID entity
        id: did + '#ocap-invoke-key-1',
        type: 'RsaSigningKey2018',
        owner: did,
        publicKeyPem: forge.pki.publicKeyToPem(invokeCapabilityKeys.publicKey)
      }
    }];
    privateDidDocument = util.deepClone(publicDidDocument);

    if(options.passphrase !== null) {
      // add the encrypted private key information to the private DID document
      privateDidDocument.authentication[0].publicKey.privateKeyPem =
        _encryptToPem(authenticationKeys.privateKey, options);
      privateDidDocument.grantCapability[0].publicKey.privateKeyPem =
        _encryptToPem(grantCapabilityKeys.privateKey, options);
      privateDidDocument.invokeCapability[0].publicKey.privateKeyPem =
        _encryptToPem(invokeCapabilityKeys.privateKey, options);
    } else {
      privateDidDocument.authentication[0].publicKey.privateKeyPem =
        forge.pki.privateKeyToPem(authenticationKeys.privateKey);
      privateDidDocument.grantCapability[0].publicKey.privateKeyPem =
        forge.pki.privateKeyToPem(grantCapabilityKeys.privateKey);
      privateDidDocument.invokeCapability[0].publicKey.privateKeyPem =
        forge.pki.privateKeyToPem(invokeCapabilityKeys.privateKey);
    }
  } else {
    const uuid = injector.use('uuid');
    publicDidDocument.id = 'did:v1:uuid:' + uuid();

    privateDidDocument = util.deepClone(publicDidDocument);
  }

  return {publicDidDocument, privateDidDocument};
});

// encrypts a given privateKey using options.passphrase and serializes to PEM
function _encryptToPem(privateKey, options) {
  const forge = api.use('forge');
  var rsaPrivateKey = forge.pki.privateKeyToAsn1(privateKey);
  const privateKeyInfo = forge.pki.wrapRsaPrivateKey(rsaPrivateKey);
  const encryptedPrivateKeyInfo = forge.pki.encryptPrivateKeyInfo(
    privateKeyInfo, options.passphrase, {algorithm: 'aes256'});

  return forge.pki.encryptedPrivateKeyToPem(encryptedPrivateKeyInfo);
}

// expose injector API
api.use = injector.use.bind(injector);

// handle dependency injection
(function() {
  const inject = options.inject || {};
  for(let name in inject) {
    api.use(name, inject[name]);
  }
})();

} // end wrap

// used to generate a new API instance
const factory = function(options) {
  return wrap(function() {return factory();}, options);
};
wrap(factory);

if(_nodejs) {
  // export nodejs API
  module.exports = factory;
} else if(typeof define === 'function' && define.amd) {
  // export AMD API
  define([], function() {
    return factory;
  });
} else if(_browser) {
  // export simple browser API
  if(typeof global.didv1 === 'undefined') {
    global.didv1 = {};
  }
  wrap(global.didv1);
}

})(typeof window !== 'undefined' ? window : this);
