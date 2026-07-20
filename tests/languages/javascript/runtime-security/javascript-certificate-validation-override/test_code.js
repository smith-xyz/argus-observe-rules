const https = require('node:https');

function overrideCheck() {
  return https.request({
    hostname: 'example.com',
    checkServerIdentity: () => undefined,
  });
}
