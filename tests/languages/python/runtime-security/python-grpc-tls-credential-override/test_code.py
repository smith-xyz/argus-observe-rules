import grpc

def insecure_grpc(target):
    channel = grpc.insecure_channel(target)
    creds = grpc.local_channel_credentials()
    return channel, creds
