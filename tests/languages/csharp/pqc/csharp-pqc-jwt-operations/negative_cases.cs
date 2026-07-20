using System;

namespace CSharpPqcJwtOperationsNegative
{
    class Program
    {
        static string BuildToken(string header, string payload)
        {
            return $"{header}.{payload}.sig";
        }
    }
}
