using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CSharpPqcMessageSigning
{
    class Program
    {
        static void MessageSigning()
        {
            byte[] data = Encoding.UTF8.GetBytes("payload");
            using var rsa = RSA.Create(2048);
            var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            using var ecdsa = ECDsa.Create();
            var ecSig = ecdsa.SignData(data, HashAlgorithmName.SHA256);
            ecdsa.VerifyData(data, ecSig, HashAlgorithmName.SHA256);

            var jws = new JsonWebSignatureHandler();
            jws.CreateToken(new SecurityTokenDescriptor());
        }
    }
}
