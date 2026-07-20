using System;
using System.Net.Http;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace CSharpHttpClientTlsOverride
{
    class Program
    {
        static void CustomClient()
        {
            var handler = new HttpClientHandler();
            handler.ClientCertificates.Add(new X509Certificate2("client.pfx"));
            handler.SslProtocols = SslProtocols.Tls12;
            var client = new HttpClient(handler);
        }
    }
}
