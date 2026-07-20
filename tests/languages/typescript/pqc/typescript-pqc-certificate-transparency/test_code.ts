import crypto from 'node:crypto';

function readScts(data) {
  const cert = new crypto.X509Certificate(data);
  return cert.signedCertificateTimestampList;
}
