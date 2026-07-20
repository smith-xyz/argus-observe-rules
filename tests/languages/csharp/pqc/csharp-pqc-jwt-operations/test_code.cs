using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;

namespace CSharpPqcJwtOperations
{
    class Program
    {
        static void JwtOperations()
        {
            var handler = new JwtSecurityTokenHandler();
            var tokenHandler = new JsonWebTokenHandler();
            var descriptor = new SecurityTokenDescriptor();
            string token = handler.CreateToken(descriptor);
            handler.ValidateToken(token, new TokenValidationParameters(), out _);
            handler.ReadJwtToken(token);
            tokenHandler.CreateToken(descriptor);
            tokenHandler.ValidateToken(token, new TokenValidationParameters());
        }
    }
}
