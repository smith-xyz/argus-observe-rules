using System.Net.Http;

namespace CSharpTlsBypassNegative
{
    class Program
    {
        static HttpClientHandler SecureHandler()
        {
            return new HttpClientHandler();
        }
    }
}
