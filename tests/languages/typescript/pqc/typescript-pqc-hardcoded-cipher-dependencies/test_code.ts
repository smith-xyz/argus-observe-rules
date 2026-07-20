import tls from 'node:tls';

function restrictCiphers() {
  const ctx = tls.createSecureContext({ ciphers: 'ECDHE-RSA-AES128-GCM-SHA256' });
  ctx.setCiphers('HIGH:!aNULL');
  return ctx;
}
