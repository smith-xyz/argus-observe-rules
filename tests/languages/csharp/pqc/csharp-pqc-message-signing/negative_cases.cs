using System;

namespace CSharpPqcMessageSigningNegative
{
    class Program
    {
        static string FakeSign(string data)
        {
            return data + ".signed";
        }
    }
}
