using System;
using Grpc.Net.Client;
using Grpc.Core;

namespace CSharpPqcGrpcTls
{
    class Program
    {
        static void GrpcTlsUsage()
        {
            var options = new GrpcChannelOptions
            {
                Credentials = ChannelCredentials.SecureSsl
            };
            var channel = GrpcChannel.ForAddress("https://localhost:5001", options);
            var insecure = ChannelCredentials.Insecure;
            var sslOptions = new SslClientAuthenticationOptions();
        }
    }
}
