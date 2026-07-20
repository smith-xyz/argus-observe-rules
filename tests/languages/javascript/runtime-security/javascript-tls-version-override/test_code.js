const tls = require('node:tls');

function limitTls() {
  return tls.connect({
    host: 'example.com',
    port: 443,
    minVersion: 'TLSv1',
    maxVersion: 'TLSv1.2',
    secureProtocol: 'TLSv1_2_method',
  });
}
