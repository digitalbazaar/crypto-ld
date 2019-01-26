/**
 * Benchmark runner for crypto-ld.
 *
 * @author Digital Bazaar
 *
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const Benchmark = require('benchmark');
const {LDKeyPair, Ed25519KeyPair, RSAKeyPair} = require('../lib/index');

// run tests
const suite = new Benchmark.Suite;

suite
  .add({
    name: 'Ed25519 generation',
    defer: true,
    fn: function(deferred) {
      Ed25519KeyPair
        .generate()
        .then(() => deferred.resolve());
    }
  })
  .add({
    name: 'RSA generation',
    defer: true,
    fn: function(deferred) {
      RSAKeyPair
        .generate()
        .then(() => deferred.resolve());
    }
  })
  .on('start', () => {
    console.log('Benchmarking...');
  })
  .on('cycle', event => {
    console.log(String(event.target));
    const s = event.target.stats;
    /*
    console.log(`  min:${Math.min(...s.sample)} max:${Math.max(...s.sample)}`);
    console.log(`  deviation:${s.deviation} mean:${s.mean}`);
    console.log(`  moe:${s.moe} rme:${s.rme}% sem:${s.sem} var:${s.variance}`);
    */
  })
  .on('complete', () => {
    console.log('Done.');
  })
  .run({async: true});
