import socket
import paramiko

class MyServer(paramiko.ServerInterface):
    pass

def start_ssh_server(sock, host_key):
    transport = paramiko.Transport(sock)
    transport.add_server_key(host_key)
    transport.start_server(server=MyServer())
    return transport
