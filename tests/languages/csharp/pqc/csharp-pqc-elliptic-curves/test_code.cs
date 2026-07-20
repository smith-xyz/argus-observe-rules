using System;
using System.Security.Cryptography;
using System.Text;

namespace CSharpPqcEllipticCurves
{
    class Program
    {
        static void EllipticCurveUsage()
        {
            byte[] data = Encoding.UTF8.GetBytes("test");
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
            var p521 = ECCurve.NamedCurves.nistP521;
            var sig = ecdsa.SignData(data, HashAlgorithmName.SHA256);
            ecdsa.VerifyData(data, sig, HashAlgorithmName.SHA256);
        }
    }
}
