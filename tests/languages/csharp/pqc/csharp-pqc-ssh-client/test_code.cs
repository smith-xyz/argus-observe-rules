using System;
using Renci.SshNet;

namespace CSharpPqcSshClient
{
    class Program
    {
        static void SshClientUsage()
        {
            var client = new SshClient("host.example.com", 22, "user", "password");
            var key = new PrivateKeyFile("/path/to/key.pem");
            var auth = new PrivateKeyAuthenticationMethod("user", key);
            var info = new ConnectionInfo("host.example.com", 22, "user", auth);
            var client2 = new SshClient(info);
            client2.HostKeyReceived += (sender, e) => { };
            client2.Connect();
        }
    }
}
