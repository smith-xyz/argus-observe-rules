using System;

namespace CSharpPqcGrpcTlsNegative
{
    class Program
    {
        static string Endpoint(string host, int port)
        {
            return $"{host}:{port}";
        }
    }
}
