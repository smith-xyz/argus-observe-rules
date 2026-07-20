const crypto = require('node:crypto');

function ecdh(curve) {
  return crypto.createECDH(curve);
}

function genEcPair(cb) {
  return crypto.generateKeyPair('ec', { namedCurve: 'P-256' }, cb);
}

function genEd25519() {
  return crypto.generateKeyPairSync('ed25519');
}

function signData(data, key) {
  return crypto.sign(null, data, key);
}
