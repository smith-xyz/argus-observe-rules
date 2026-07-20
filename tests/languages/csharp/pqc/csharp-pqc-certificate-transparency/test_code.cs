using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace CSharpPqcCertificateTransparency
{
    class Program
    {
        static void CtUsage()
        {
            var cert = new X509Certificate2("cert.pem");
            var extensions = cert.Extensions;
            var sct = extensions.Cast<X509Extension>().FirstOrDefault();
            if (sct != null)
            {
                var raw = sct.RawData;
            }
            var oid = new Oid("1.3.6.1.4.1.11129.2.4.2");
            var ext = new X509Extension(oid, new byte[] { 0x04, 0x03 }, false);
        }
    }
}
