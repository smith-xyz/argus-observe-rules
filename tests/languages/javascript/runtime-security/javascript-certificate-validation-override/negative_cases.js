const https = require('node:https');

function secureRequest() {
  return https.request({ hostname: 'example.com' });
}
