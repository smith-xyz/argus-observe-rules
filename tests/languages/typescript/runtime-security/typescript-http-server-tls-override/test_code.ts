import https from 'node:https';
import tls from 'node:tls';

function serveTls(options, handler) {
  const server = https.createServer(options, handler);
  const alt = tls.createServer(options, handler);
  return { server, alt };
}
