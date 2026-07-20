import https from 'node:https';

function secureAgent() {
  return new https.Agent({ rejectUnauthorized: true });
}
