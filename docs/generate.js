/**
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import jsdoc2md from 'jsdoc-to-markdown';
import fs from 'node:fs';

const template = fs.readFileSync('./docs/template.hbs', 'utf-8');
const opFactory = file => ({template, files: `./lib/${file}`});

// we only generate docs for files which end with keypair or index.
const docs = /(keypair|index).js/i;
const files = fs.readdirSync('./lib')
  .filter(p => docs.test(p));
files.forEach(filePath => {
  const options = opFactory(filePath);
  const doc = jsdoc2md.renderSync(options);
  // if the doc is smaller than the template there was
  // no actual content inserted into main.
  if(!doc || doc.length < template.length) {
    return false;
  }
  const fpath = filePath;
  const docFileName = './docs/' + fpath.replace(/.js/, '.md');
  fs.writeFileSync(docFileName, doc);
});
