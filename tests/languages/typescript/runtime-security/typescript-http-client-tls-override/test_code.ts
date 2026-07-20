import https from 'node:https';
import axios from 'axios';

function customClient() {
  const agent = new https.Agent({ keepAlive: true });
  const client = axios.create({ httpsAgent: agent });
  return client;
}
