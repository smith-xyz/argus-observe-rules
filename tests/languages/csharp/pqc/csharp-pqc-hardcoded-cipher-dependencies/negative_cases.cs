using System.Net.Http;

namespace CSharpPqcHardcodedCipherDependenciesNegative
{
    class Program
    {
        static HttpClientHandler DefaultHandler()
        {
            return new HttpClientHandler();
        }
    }
}
