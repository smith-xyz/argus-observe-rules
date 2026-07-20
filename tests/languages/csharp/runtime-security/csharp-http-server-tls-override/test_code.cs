using System;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace CSharpHttpServerTlsOverride
{
    class Program
    {
        static void ServeTls(Stream stream, X509Certificate2 cert, IWebHostBuilder builder)
        {
            var ssl = new SslStream(stream, false);
            var ssl2 = new SslStream(stream, leaveInnerStreamOpen: false);
            builder.UseHttps(cert);
            builder.UseKestrel(options => { });
        }
    }
}
