using System;

namespace CSharpPqcCertificateTransparencyNegative
{
    class Program
    {
        static string CtUrl(string baseUrl)
        {
            return $"{baseUrl}/ct/v1/get-sth";
        }
    }
}
