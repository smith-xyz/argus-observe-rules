import paramiko

def ssh_connect(hostname, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname, username=username, password=password)
    return client

def load_key(path):
    return paramiko.RSAKey.from_private_key_file(path)
