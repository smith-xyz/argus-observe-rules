const https = require('node:https');
const axios = require('axios');

function customClient() {
  const agent = new https.Agent({ keepAlive: true });
  const client = axios.create({ httpsAgent: agent });
  return client;
}
