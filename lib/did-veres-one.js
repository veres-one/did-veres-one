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

const constants = {
  VERES_ONE_V1_CONTEXT: 'https://w3id.org/veres-one/v1'
};

/**
 * Attaches the JSON-LD Signatures API to the given object.
 *
 * @param api the object to attach the signatures API to.
 */
function wrap(api) {

const injector = new Injector();

/* Core API */
api.constants = constants;

/**
 * Generate a new DID Document.
 */
api.generate = util.callbackify(async function(
  {didType = 'nym', keyType = 'RsaSigningKey2018', passphrase}) {
  const publicDidDocument = {
    '@context': constants.VERES_ONE_V1_CONTEXT,
  };
  let privateDidDocument = null;

  // passphrase is a required parameter if generating a nym-based DID
  if(didType === 'nym' && passphrase === undefined) {
    throw new TypeError('"options.passphrase" must be specified.');
  }

  if(didType === 'nym') {
    if(keyType !== 'RsaSigningKey2018') {
      throw new Error(`Unknown key type: "${keyType}"`);
    }

    // generate the nym-based DID
    const forge = injector.use('forge');
    const keyBits = (keyType === 'RsaSigningKey2018') ? 2048 : 2048;

    // application suite parameters
    const appSuites = {
      // for authenticating as DID entity
      authentication: {
        type: 'RsaSignatureAuthentication2018',
        publicKeyHash: 'authn-key-1'
      },
      // for granting capabilities as DID entity
      grantCapability: {
        type: 'RsaSignatureCapabilityAuthorization2018',
        publicKeyHash: 'ocap-grant-key-1'
      },
      // for invoking capabilities as DID entity
      invokeCapability: {
        type: 'RsaSignatureCapabilityAuthorization2018',
        publicKeyHash: 'ocap-invoke-key-1'
      }
    };

    // generate a separate key pair for each app suite
    for(const name in appSuites) {
      appSuites[name].keys = await _generateRsaKeyPair(keyBits);
    }

    // generate nym using authentication app suite
    const fingerprintBuffer = forge.pki.getPublicKeyFingerprint(
      appSuites.authentication.keys.publicKey, {
      md: forge.md.sha256.create()
    });
    const did = 'did:v1:nym:' + util.encodeBase64Url(
      fingerprintBuffer.bytes(), {forge});

    publicDidDocument.id = did;

    // add app suites to DID Document
    for(const name in appSuites) {
      const appSuite = appSuites[name];
      publicDidDocument[name] = [{
        type: appSuite.type,
        publicKey: {
          id: did + '#' + appSuite.publicKeyHash,
          type: keyType,
          owner: did,
          publicKeyPem: forge.pki.publicKeyToPem(appSuite.keys.publicKey)
        }
      }];
    }

    // add private key information to the private DID document
    privateDidDocument = util.deepClone(publicDidDocument);
    for(const name in appSuites) {
      const {privateKey} = appSuites[name].keys;
      const {publicKey} = privateDidDocument[name][0];
      if(passphrase !== null) {
        // passphrase provided, so encrypt private key
        publicKey.privateKeyPem = forge.pki.encryptRsaPrivateKey(
          privateKey, passphrase, {algorithm: 'aes256'});
      } else {
        // no passphrase, do not encrypt private key
        publicKey.privateKeyPem = forge.pki.privateKeyToPem(privateKey);
      }
    }
  } else {
    const uuid = injector.use('uuid');
    publicDidDocument.id = 'did:v1:uuid:' + uuid();

    privateDidDocument = util.deepClone(publicDidDocument);
  }

  return {publicDidDocument, privateDidDocument};
});

/**
 * Wrap a DID Document in a Web Ledger Operation.
 */
api.wrap = ({didDocument, operationType = 'create'}) => {
  switch(operationType) {
    case 'create':
      operationType = 'CreateWebLedgerRecord';
      break;
    default:
      throw new Error(`Unknown operation type "${operationType}"`);
  }

  return {
    '@context': constants.VERES_ONE_V1_CONTEXT,
    type: operationType,
    record: didDocument
  };
};

/**
 * Add an ocap invocation proof to an operation.
 */
api.attachInvocationProof = util.callbackify(async function(
  // TODO: support `passphrase` for encrypted private key pem or keep decrypt
  //   as the responsibility of the caller?
  {operation, capability, capabilityAction, creator, privateKeyPem}) {
  // FIXME: use ldocap.js

  // FIXME: validate operation, capability, creator, and privateKeyPem
  // TODO: support `signer` API as alternative to `privateKeyPem`
  const jsigs = injector.use('jsonld-signatures');
  return jsigs.sign(operation, {
    algorithm: 'RsaSignature2018',
    creator,
    privateKeyPem: privateKeyPem,
    proof: {
      '@context': constants.VERES_ONE_V1_CONTEXT,
      proofPurpose: 'invokeCapability',
      capability,
      capabilityAction
    }
  });
});

async function _generateRsaKeyPair(keyBits) {
  const forge = injector.use('forge');

  if(injector.env.nodejs) {
    const ursa = require('ursa');
    const exponent = 0x10001;
    const keypair = ursa.generatePrivateKey(keyBits, exponent);
    return {
      privateKey: forge.pki.privateKeyFromPem(keypair.toPrivatePem()),
      publicKey: forge.pki.publicKeyFromPem(keypair.toPublicPem())
    };
  }

  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({bits: keyBits}, (err, keypair) => {
      if(err) {
        return reject(err);
      }
      resolve(keypair);
    });
  });
}

// expose injector API
api.use = injector.use.bind(injector);

} // end wrap

// used to generate a new API instance
const factory = function() {
  return wrap(function() {return factory();});
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
