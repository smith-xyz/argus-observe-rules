using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;

namespace CSharpTlsVersionOverride
{
    class Program
    {
        static void LimitTls()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            var handler = new HttpClientHandler();
            handler.SslProtocols = SslProtocols.Tls;
            handler.SslProtocols = SslProtocols.Tls11;
            handler.SslProtocols = SslProtocols.Tls12;
            var legacy = SecurityProtocolType.Tls11;
        }
    }
}
