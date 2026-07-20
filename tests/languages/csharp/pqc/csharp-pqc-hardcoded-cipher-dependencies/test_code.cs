using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;

namespace CSharpPqcHardcodedCipherDependencies
{
    class Program
    {
        static void RestrictCiphers()
        {
            var handler = new HttpClientHandler();
            handler.SslProtocols = SslProtocols.Tls12;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            handler.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11;
        }
    }
}
