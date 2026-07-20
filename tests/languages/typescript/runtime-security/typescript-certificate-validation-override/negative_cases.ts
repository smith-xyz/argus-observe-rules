import https from 'node:https';

function secureRequest() {
  return https.request({ hostname: 'example.com' });
}
