const { Server } = require('ssh2');

function startServer(port, host) {
  const server = new Server({}, (client) => {
    client.on('authentication', () => {});
  });
  server.listen(port, host, () => {});
  return server;
}
