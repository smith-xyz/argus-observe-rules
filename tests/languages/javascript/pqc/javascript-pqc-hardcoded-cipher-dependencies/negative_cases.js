const tls = require('node:tls');

function defaultContext() {
  return tls.createSecureContext();
}
