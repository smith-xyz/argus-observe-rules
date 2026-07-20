using System;
using System.Net;
using System.Net.Http;

namespace CSharpTlsBypass
{
    class Program
    {
        static void BypassTls()
        {
            ServicePointManager.ServerCertificateValidationCallback =
                delegate { return true; };

            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback =
                (request, cert, chain, errors) => true;
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }
    }
}
