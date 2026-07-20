using System;
using System.Net.Http;
using System.Security.Cryptography;
using Grpc.Net.Client;

namespace CSharpPqcConfigProfileDependencies
{
    class Program
    {
        static void ConfigUsage()
        {
            var fipsEnv = Environment.GetEnvironmentVariable("COMPlus_EnableDiagnostics");
            var handlerEnv = Environment.GetEnvironmentVariable("DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER");
            var fipsOnly = CryptoConfig.AllowOnlyFipsAlgorithms;
            var handler = new HttpClientHandler();
            var channel = GrpcChannel.ForAddress("https://localhost:5001");
        }
    }
}
