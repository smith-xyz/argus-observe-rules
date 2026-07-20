using System;

namespace CSharpPqcOAuthJwtSamlNegative
{
    class Program
    {
        static string ParseBearer(string header)
        {
            return header.Replace("Bearer ", "");
        }
    }
}
