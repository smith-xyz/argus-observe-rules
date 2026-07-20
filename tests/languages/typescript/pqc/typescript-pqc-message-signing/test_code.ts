import crypto from 'node:crypto';
import jose from 'jose';

function rsaSign(data, key) {
  return crypto.sign('RSA-SHA256', data, key);
}

async function jwsSign(payload, key) {
  return await new jose.SignJWT(payload).setProtectedHeader({ alg: 'RS256' }).sign(key);
}
