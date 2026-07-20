const jwt = require('jsonwebtoken');

function signHs256(payload, key) {
  return jwt.sign(payload, key, { algorithm: 'HS256' });
}
