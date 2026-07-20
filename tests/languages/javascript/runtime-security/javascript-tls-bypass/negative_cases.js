const https = require('node:https');

function secureAgent() {
  return new https.Agent({ rejectUnauthorized: true });
}
