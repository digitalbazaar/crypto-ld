/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asn1, oids, util: {ByteBuffer}} = require('node-forge');
const {createPrivateKey} = require('crypto');

exports.create = ({privateKeyBytes, seedBytes}) => createPrivateKey({
  key: exports._derEncode({privateKeyBytes, seedBytes}),
  format: 'der',
  type: 'pkcs8'
});

// exported for testing
exports._derEncode = ({privateKeyBytes, seedBytes}) => {
  if(!(privateKeyBytes || seedBytes)) {
    throw new TypeError('`privateKeyBytes` or `seedBytes` is required.');
  }
  if(!privateKeyBytes && !(Buffer.isBuffer(seedBytes) &&
    seedBytes.length === 32)) {
    throw new TypeError('`seedBytes` must be a 32 byte Buffer.');
  }
  if(!seedBytes && !(Buffer.isBuffer(privateKeyBytes) &&
    privateKeyBytes.length === 64)) {
    throw new TypeError('`privateKeyBytes` must be a 64 byte Buffer.');
  }
  let p;
  if(seedBytes) {
    p = seedBytes;
  } else {
    // extract the first 32 bytes of the 64 byte private key representation
    p = Buffer.from(privateKeyBytes.buffer, privateKeyBytes.byteOffset, 32);
  }
  const keyBuffer = new ByteBuffer(p);

  const asn1Key = asn1.create(
    asn1.UNIVERSAL,
    asn1.Type.OCTETSTRING,
    false,
    keyBuffer.getBytes()
  );

  const a = asn1.create(
    asn1.Class.UNIVERSAL,
    asn1.Type.SEQUENCE,
    true, [
      asn1.create(
        asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
        asn1.integerToDer(0).getBytes()),
      // privateKeyAlgorithm
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(
          asn1.Class.UNIVERSAL,
          asn1.Type.OID,
          false,
          asn1.oidToDer(oids.EdDSA25519).getBytes()
        ),
      ]),
      // private key
      asn1.create(
        asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
        asn1.toDer(asn1Key).getBytes()),
    ]
  );

  const privateKeyDer = asn1.toDer(a);
  return Buffer.from(privateKeyDer.getBytes(), 'binary');
};
