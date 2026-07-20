using System;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Client;
using Sustainsys.Saml2.Configuration;

namespace CSharpPqcOAuthJwtSaml
{
    class Program
    {
        static void IdentityProtocols()
        {
            var oidc = new OpenIdConnectOptions();
            oidc.Authority = "https://auth.example.com";
            oidc.ClientId = "client-id";

            var saml = new Saml2Configuration();
            saml.SigningCertificate = new System.Security.Cryptography.X509Certificates.X509Certificate2();

            var app = ConfidentialClientApplicationBuilder
                .Create("client-id")
                .WithClientSecret("secret")
                .Build();
        }
    }
}
