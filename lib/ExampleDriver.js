/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

/**
 * Example key suite driver for use with CryptoLd. When adding support for
 * a new suite type for `crypto-ld`, developers should do the following:
 *
 * 1. Create their own npm package / github repo, such as `example-key-pair`.
 * 2. Create a driver module that implements the functions in this example
 *   interface, in this new repo.
 * 3. Create a new key pair class that extends from `LDKeyPair` class, in this
 *   new repo.
 * 4. Add to the key type table in the `crypto-ld` README.md (that's this repo).
 * 5. Add to the SUITES_BY_TYPE map in `CryptoLd.js`.
 */

/**
 * @param {object} options - Suite-specific key generation options.
 *
 * @returns {Promise<LDKeyPair>} Instance of an LDKeyPair subclass.
 */
async function generate(/* options = {} */) {}

/**
 * @param {object} serialized - Serialized key pair object.
 *
 * @returns {<LDKeyPair>} Instance of an LDKeyPair subclass.
 */
function from(/* serialized */) {}

module.exports = {
  suite: 'ExampleVerificationKey20xx',
  generate,
  from
};
