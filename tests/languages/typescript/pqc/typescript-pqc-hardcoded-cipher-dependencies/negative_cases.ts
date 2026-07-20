import tls from 'node:tls';

function defaultContext() {
  return tls.createSecureContext();
}
