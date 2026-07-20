import { Client } from 'ssh2';

function sshConnect(config) {
  const client = new Client();
  client.on('hostkey', () => {});
  client.connect(config);
  return client;
}
