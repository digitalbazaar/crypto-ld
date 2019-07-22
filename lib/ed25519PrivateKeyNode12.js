/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {createPrivateKey} = require('crypto');
const {privateKeyDerEncode} = require('./util');

exports.create = ({privateKeyBytes, seedBytes}) => createPrivateKey({
  key: privateKeyDerEncode({privateKeyBytes, seedBytes}),
  format: 'der',
  type: 'pkcs8'
});
