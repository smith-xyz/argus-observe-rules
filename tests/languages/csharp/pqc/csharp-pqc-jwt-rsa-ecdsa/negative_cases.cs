using Microsoft.IdentityModel.Tokens;

namespace CSharpPqcJwtRsaEcdsaNegative
{
    class Program
    {
        static void HmacOnly()
        {
            var cred = new SigningCredentials(new SymmetricSecurityKey(new byte[32]), SecurityAlgorithms.HmacSha256);
        }
    }
}
