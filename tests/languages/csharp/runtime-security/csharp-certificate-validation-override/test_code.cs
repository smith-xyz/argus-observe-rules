using System;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace CSharpCertificateValidationOverride
{
    class Program
    {
        static bool AlwaysValid(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
        {
            return true;
        }

        static void OverrideValidation()
        {
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback =
                (request, cert, chain, errors) => true;
            handler.ServerCertificateCustomValidationCallback =
                (request, cert, chain, errors) => { return true; };
            var callback = new RemoteCertificateValidationCallback(AlwaysValid);
        }
    }
}
