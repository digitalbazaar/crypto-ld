/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asn1, oids, util: {ByteBuffer}} = require('node-forge');
const {createPublicKey} = require('crypto');

exports.create = ({publicKeyBytes}) => createPublicKey({
  key: exports._derEncode({publicKeyBytes}),
  format: 'der',
  type: 'spki'
});

exports._derEncode = ({publicKeyBytes}) => {
  if(!(Buffer.isBuffer(publicKeyBytes) && publicKeyBytes.length === 32)) {
    throw new TypeError('`publicKeyBytes` must be a 32 byte Buffer.');
  }
  // add a zero byte to the front of the publicKeyBytes, this results in
  // the bitstring being 256 bits vs. 170 bits (without padding)
  const zeroBuffer = Buffer.from(new Uint8Array([0]));
  const keyBuffer = new ByteBuffer(Buffer.concat([zeroBuffer, publicKeyBytes]));

  const a = asn1.create(
    asn1.Class.UNIVERSAL,
    asn1.Type.SEQUENCE,
    true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(
          asn1.Class.UNIVERSAL,
          asn1.Type.OID,
          false,
          asn1.oidToDer(oids.EdDSA25519).getBytes()
        ),
      ]),
      // public key
      asn1.create(
        asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false,
        keyBuffer.getBytes()),
    ]
  );

  const publicKeyDer = asn1.toDer(a);
  return Buffer.from(publicKeyDer.getBytes(), 'binary');
};
