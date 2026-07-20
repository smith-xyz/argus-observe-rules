import tls from 'node:tls';
import grpc from '@grpc/grpc-js';

function readConfig() {
  const opts = process.env.NODE_OPTIONS;
  const conf = process.env.OPENSSL_CONF;
  const ctx = tls.createSecureContext({ minVersion: 'TLSv1.2' });
  const client = new grpc.Client('localhost:50051', grpc.credentials.createInsecure());
  return { opts, conf, ctx, client };
}
