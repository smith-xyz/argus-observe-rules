import jwt from 'jsonwebtoken';

function createToken(payload, key) {
  return jwt.sign(payload, key, { algorithm: 'HS256' });
}

function verifyToken(token, key) {
  return jwt.verify(token, key, { algorithms: ['HS256'] });
}

function decodeToken(token) {
  return jwt.decode(token, { complete: true });
}
