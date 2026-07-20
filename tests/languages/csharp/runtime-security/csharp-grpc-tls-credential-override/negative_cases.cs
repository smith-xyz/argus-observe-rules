using System;

namespace CSharpGrpcTlsCredentialOverrideNegative
{
    class Program
    {
        static string GrpcTarget(string host, int port)
        {
            return $"{host}:{port}";
        }
    }
}
