import tls from 'node:tls';

function modernTls() {
  return tls.connect({ host: 'example.com', port: 443, minVersion: 'TLSv1.2' });
}
