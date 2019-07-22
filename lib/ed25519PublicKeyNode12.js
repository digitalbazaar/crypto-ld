/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {createPublicKey} = require('crypto');
const {publicKeyDerEncode} = require('./util');

exports.create = ({publicKeyBytes}) => createPublicKey({
  key: publicKeyDerEncode({publicKeyBytes}),
  format: 'der',
  type: 'spki'
});
