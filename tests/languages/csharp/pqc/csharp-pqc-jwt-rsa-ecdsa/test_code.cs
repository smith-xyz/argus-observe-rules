using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace CSharpPqcJwtRsaEcdsa
{
    class Program
    {
        static void JwtRsaEcdsa()
        {
            var rsaCred = new SigningCredentials(new RsaSecurityKey(RSA.Create()), SecurityAlgorithms.RsaSha256);
            var esCred = new SigningCredentials(new ECDsaSecurityKey(ECDsa.Create()), SecurityAlgorithms.EcdsaSha256);
            var rs384 = SecurityAlgorithms.RsaSha384;
            var es512 = SecurityAlgorithms.EcdsaSha512;
            var pss = SecurityAlgorithms.RsaSsaPssSha256;
        }
    }
}
