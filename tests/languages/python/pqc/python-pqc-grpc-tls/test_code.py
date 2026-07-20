import grpc

def connect_secure(target, creds):
    return grpc.secure_channel(target, creds)

def connect_insecure(target):
    return grpc.insecure_channel(target)

def make_creds(root, key, chain):
    return grpc.ssl_channel_credentials(root, key, chain)
