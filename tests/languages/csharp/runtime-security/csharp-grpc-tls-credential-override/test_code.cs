using System;
using Grpc.Net.Client;
using Grpc.Core;

namespace CSharpGrpcTlsCredentialOverride
{
    class Program
    {
        static void InsecureGrpc()
        {
            var creds = ChannelCredentials.Insecure;
            var channel = GrpcChannel.ForAddress(
                "http://localhost:5000",
                new GrpcChannelOptions { Credentials = ChannelCredentials.Insecure });
            var options = new GrpcChannelOptions();
            options.Credentials = ChannelCredentials.Insecure;
        }
    }
}
