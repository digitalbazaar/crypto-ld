/*
 * Copyright (c) 2018-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {CryptoLd, SUITES_BY_TYPE} = require('./CryptoLd');
const {LDKeyPair} = require('./LDKeyPair');

module.exports = {
  cryptoLd: new CryptoLd(),
  LDKeyPair,
  SUITES_BY_TYPE
};
