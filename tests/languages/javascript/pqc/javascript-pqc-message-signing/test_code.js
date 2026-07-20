const crypto = require('node:crypto');
const jose = require('jose');

function rsaSign(data, key) {
  return crypto.sign('RSA-SHA256', data, key);
}

async function jwsSign(payload, key) {
  return await new jose.SignJWT(payload).setProtectedHeader({ alg: 'RS256' }).sign(key);
}
