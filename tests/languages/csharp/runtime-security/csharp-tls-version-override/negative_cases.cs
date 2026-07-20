using System.Net.Http;

namespace CSharpTlsVersionOverrideNegative
{
    class Program
    {
        static HttpClientHandler ModernHandler()
        {
            return new HttpClientHandler();
        }
    }
}
