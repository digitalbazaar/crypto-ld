mkdir ./dist/esm
cat >dist/esm/index.js <<!EOF
import cjsModule from '../index.js';
export const LDKeyPair = cjsModule.LDKeyPair;
export const CryptoLD = cjsModule.CryptoLD;
!EOF

cat >dist/esm/package.json <<!EOF
{
  "type": "module"
}
!EOF
