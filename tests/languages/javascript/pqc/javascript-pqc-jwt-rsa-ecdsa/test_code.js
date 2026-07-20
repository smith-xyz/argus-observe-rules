const jwt = require('jsonwebtoken');

function signRs256(payload, key) {
  return jwt.sign(payload, key, { algorithm: 'RS256' });
}

function signEs256(payload, key) {
  return jwt.sign(payload, key, { algorithm: 'ES256' });
}

function verifyRs256(token, key) {
  return jwt.verify(token, key, { algorithms: ['RS256'] });
}
