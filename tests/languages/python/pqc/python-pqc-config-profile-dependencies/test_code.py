import os
import ssl
import grpc

def check_fips():
    return os.environ.get("OPENSSL_FIPS")

def tls_context():
    return ssl.create_default_context()

def grpc_connect(target, creds):
    return grpc.secure_channel(target, creds)
