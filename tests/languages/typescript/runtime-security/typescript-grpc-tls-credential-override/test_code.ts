import grpc from '@grpc/grpc-js';

function insecureGrpc(target) {
  const creds = grpc.credentials.createInsecure();
  return new grpc.Client(target, grpc.credentials.createInsecure());
}
