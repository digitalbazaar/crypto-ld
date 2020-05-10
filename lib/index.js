/*
 * Copyright (c) 2018-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

module.exports = {
  CryptoLD: require('./cryptoLd'),
  LDKeyPair: require('./LDKeyPair'),
  cryptoLd: new CryptoLd()
};
