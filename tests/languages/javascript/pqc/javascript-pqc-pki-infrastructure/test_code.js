const crypto = require('node:crypto');
const forge = require('node-forge');

function loadCert(data) {
  const cert = new crypto.X509Certificate(data);
  cert.checkIssued(cert);
  cert.verify(cert.publicKey);
  return cert;
}

function loadForgeCert(pem) {
  return forge.pki.certificateFromPem(pem);
}
