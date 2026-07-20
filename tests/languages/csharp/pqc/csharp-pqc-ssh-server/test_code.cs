using System;
using Renci.SshNet;
using System.Net;
using System.Net.Sockets;

namespace CSharpPqcSshServer
{
    class Program
    {
        static void SshServerUsage()
        {
            var sftp = new SftpClient("host.example.com", 22, "user", "password");
            var key = new PrivateKeyFile("/path/to/host_key.pem");
            var auth = new PrivateKeyAuthenticationMethod("user", key);
            var info = new ConnectionInfo("host.example.com", 22, "user", auth);
            var scp = new ScpClient(info);

            var listener = new TcpListener(IPAddress.Any, 22);
            listener.Start();
            var socket = listener.AcceptSocket();
        }
    }
}
