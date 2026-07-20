const grpc = require('@grpc/grpc-js');

function secureClient(target, roots, key, cert) {
  return new grpc.Client(target, grpc.credentials.createSsl(roots, key, cert));
}

function insecureCreds() {
  return grpc.credentials.createInsecure();
}

function grpcServer() {
  return new grpc.Server();
}
