import https from 'node:https';
import axios from 'axios';

function bypassTls() {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  const agent = new https.Agent({ rejectUnauthorized: false });
  agent.options.rejectUnauthorized = false;
  return axios.get('https://example.com', { httpsAgent: agent });
}
