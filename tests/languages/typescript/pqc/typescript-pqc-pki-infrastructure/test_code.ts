import crypto from 'node:crypto';
import forge from 'node-forge';

function loadCert(data) {
  const cert = new crypto.X509Certificate(data);
  cert.checkIssued(cert);
  cert.verify(cert.publicKey);
  return cert;
}

function loadForgeCert(pem) {
  return forge.pki.certificateFromPem(pem);
}
