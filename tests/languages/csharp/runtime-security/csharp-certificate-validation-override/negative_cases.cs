using System.Net.Http;

namespace CSharpCertificateValidationOverrideNegative
{
    class Program
    {
        static HttpClientHandler SecureHandler()
        {
            return new HttpClientHandler();
        }
    }
}
