using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CSharpPqcPkiInfrastructure
{
    class Program
    {
        static void PkiUsage()
        {
            var cert = new X509Certificate2("cert.pem");
            var fromPem = X509Certificate2.CreateFromPemFile("cert.pem");
            var chain = new X509Chain();
            chain.Build(cert);
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=example", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var selfSigned = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            cert.GetPublicKey();
            cert.Verify();
        }
    }
}
