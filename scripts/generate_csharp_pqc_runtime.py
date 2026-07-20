#!/usr/bin/env python3
"""Generate C# PQC and runtime-security rules with tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_PQC = ROOT / "rules/languages/csharp/pqc"
RULES_RT = ROOT / "rules/languages/csharp/runtime-security"
TESTS = ROOT / "tests/languages/csharp"
EXT = "cs"

RULES: dict[str, dict] = {
    # --- PQC ---
    "csharp-pqc-jwt-operations": {
        "category": "pqc",
        "yaml": """rules:
  - id: csharp-pqc-jwt-operations
    message: "JWT token operations detected - verify PQC signature algorithm support"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: new JwtSecurityTokenHandler()
          - pattern: $HANDLER.CreateToken($DESCRIPTOR)
          - pattern: $HANDLER.ValidateToken($TOKEN, $PARAMS, out $VALIDATED)
          - pattern: $HANDLER.ReadJwtToken($TOKEN)
          - pattern: new JsonWebTokenHandler()
          - pattern: $JWT_HANDLER.CreateToken($DESCRIPTOR)
          - pattern: $JWT_HANDLER.ValidateToken($TOKEN, $PARAMS)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: JWT infrastructure may need updates for PQC signature algorithms
""",
        "test": """using System;
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
""",
        "negative": """using System;

namespace CSharpPqcJwtOperationsNegative
{
    class Program
    {
        static string BuildToken(string header, string payload)
        {
            return $"{header}.{payload}.sig";
        }
    }
}
""",
    },
    "csharp-pqc-jwt-rsa-ecdsa": {
        "category": "pqc",
        "yaml": """rules:
  - id: csharp-pqc-jwt-rsa-ecdsa
    message: "JWT with RSA/ECDSA signatures detected - assess PQC signature algorithm support readiness"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: SecurityAlgorithms.RsaSha256
          - pattern: SecurityAlgorithms.RsaSha384
          - pattern: SecurityAlgorithms.RsaSha512
          - pattern: SecurityAlgorithms.EcdsaSha256
          - pattern: SecurityAlgorithms.EcdsaSha384
          - pattern: SecurityAlgorithms.EcdsaSha512
          - pattern: SecurityAlgorithms.RsaSsaPssSha256
          - pattern: SigningCredentials($KEY, SecurityAlgorithms.RsaSha256)
          - pattern: SigningCredentials($KEY, SecurityAlgorithms.EcdsaSha256)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "JWT signature algorithms catalogued - verify JWT library supports hybrid or PQC signature methods"
""",
        "test": """using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace CSharpPqcJwtRsaEcdsa
{
    class Program
    {
        static void JwtRsaEcdsa()
        {
            var rsaCred = new SigningCredentials(new RsaSecurityKey(RSA.Create()), SecurityAlgorithms.RsaSha256);
            var esCred = new SigningCredentials(new ECDsaSecurityKey(ECDsa.Create()), SecurityAlgorithms.EcdsaSha256);
            var rs384 = SecurityAlgorithms.RsaSha384;
            var es512 = SecurityAlgorithms.EcdsaSha512;
            var pss = SecurityAlgorithms.RsaSsaPssSha256;
        }
    }
}
""",
        "negative": """using Microsoft.IdentityModel.Tokens;

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
""",
    },
    "csharp-pqc-oauth-jwt-saml": {
        "category": "pqc",
        "yaml": """rules:
  - id: csharp-pqc-oauth-jwt-saml
    message: "OAuth/SAML/OIDC operations detected - assess identity protocol PQC signature readiness"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: AddOpenIdConnect($OPTIONS)
          - pattern: OpenIdConnectOptions
          - pattern: $OPTIONS.Authority = $AUTHORITY
          - pattern: $OPTIONS.ClientId = $CLIENT_ID
          - pattern: AddSaml2($OPTIONS)
          - pattern: new Saml2Configuration()
          - pattern: $CONFIG.SigningCertificate = $CERT
          - pattern: ConfidentialClientApplicationBuilder.Create($CLIENT_ID)
          - pattern: $BUILDER.WithClientSecret($SECRET)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "Identity protocol usage documented - verify OAuth/SAML/OIDC libraries support hybrid or PQC signature algorithms"
""",
        "test": """using System;
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
""",
        "negative": """using System;

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
""",
    },
    "csharp-pqc-ssh-client": {
        "category": "pqc",
        "yaml": """rules:
  - id: csharp-pqc-ssh-client
    message: "SSH client configuration detected - evaluate PQC SSH algorithm support readiness"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: new SshClient($HOST, $PORT, $USERNAME, $PASSWORD)
          - pattern: new SshClient($CONNECTION_INFO)
          - pattern: new ConnectionInfo($HOST, $PORT, $USERNAME, $AUTH)
          - pattern: new PrivateKeyFile($PATH)
          - pattern: new PrivateKeyFile($PATH, $PASSPHRASE)
          - pattern: $CLIENT.Connect()
          - pattern: $CLIENT.HostKeyReceived += $HANDLER
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "SSH client configuration documented - verify SSH library supports hybrid or PQC key exchange and authentication algorithms"
""",
        "test": """using System;
using Renci.SshNet;

namespace CSharpPqcSshClient
{
    class Program
    {
        static void SshClientUsage()
        {
            var client = new SshClient("host.example.com", 22, "user", "password");
            var key = new PrivateKeyFile("/path/to/key.pem");
            var auth = new PrivateKeyAuthenticationMethod("user", key);
            var info = new ConnectionInfo("host.example.com", 22, "user", auth);
            var client2 = new SshClient(info);
            client2.HostKeyReceived += (sender, e) => { };
            client2.Connect();
        }
    }
}
""",
        "negative": """using System;

namespace CSharpPqcSshClientNegative
{
    class Program
    {
        static string SshCommand(string host, string user)
        {
            return $"ssh {user}@{host}";
        }
    }
}
""",
    },
    "csharp-pqc-ssh-server": {
        "category": "pqc",
        "yaml": """rules:
  - id: csharp-pqc-ssh-server
    message: "SSH server configuration detected - assess PQC SSH algorithm implementation capability"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: new SftpClient($HOST, $PORT, $USERNAME, $PASSWORD)
          - pattern: new ScpClient($CONNECTION_INFO)
          - pattern: new PrivateKeyAuthenticationMethod($USERNAME, $KEY_FILE)
          - pattern: $SERVER.Start()
          - pattern: $SERVER.Accept()
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "SSH server configuration catalogued - verify SSH server supports hybrid host keys and PQC algorithms"
""",
        "test": """using System;
using Renci.SshNet;
using System.Net;
using System.Net.Sockets;

namespace CSharpPqcSshServer
{
    class Program
    {
        static void SshServerUsage()
        {
            var sftp = new SftpClient("host.example.com", 22, "user", "password");
            var key = new PrivateKeyFile("/path/to/host_key.pem");
            var auth = new PrivateKeyAuthenticationMethod("user", key);
            var info = new ConnectionInfo("host.example.com", 22, "user", auth);
            var scp = new ScpClient(info);

            var listener = new TcpListener(IPAddress.Any, 22);
            listener.Start();
            var socket = listener.AcceptSocket();
        }
    }
}
""",
        "negative": """using System;

namespace CSharpPqcSshServerNegative
{
    class Program
    {
        static int SshPort(int port)
        {
            return port;
        }
    }
}
""",
    },
    "csharp-pqc-grpc-tls": {
        "category": "pqc",
        "yaml": """rules:
  - id: csharp-pqc-grpc-tls
    message: "gRPC TLS configuration detected - evaluate hybrid TLS and certificate support capability"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: GrpcChannel.ForAddress($ADDRESS, $OPTIONS)
          - pattern: new GrpcChannelOptions()
          - pattern: ChannelCredentials.SecureSsl
          - pattern: ChannelCredentials.Insecure
          - pattern: SslClientAuthenticationOptions
          - pattern: $OPTIONS.Credentials = $CREDS
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "gRPC TLS configuration documented - verify gRPC supports hybrid certificates and PQC cipher suites"
""",
        "test": """using System;
using Grpc.Net.Client;
using Grpc.Core;

namespace CSharpPqcGrpcTls
{
    class Program
    {
        static void GrpcTlsUsage()
        {
            var options = new GrpcChannelOptions
            {
                Credentials = ChannelCredentials.SecureSsl
            };
            var channel = GrpcChannel.ForAddress("https://localhost:5001", options);
            var insecure = ChannelCredentials.Insecure;
            var sslOptions = new SslClientAuthenticationOptions();
        }
    }
}
""",
        "negative": """using System;

namespace CSharpPqcGrpcTlsNegative
{
    class Program
    {
        static string Endpoint(string host, int port)
        {
            return $"{host}:{port}";
        }
    }
}
""",
    },
    "csharp-pqc-pki-infrastructure": {
        "category": "pqc",
        "yaml": """rules:
  - id: csharp-pqc-pki-infrastructure
    message: "PKI and X.509 certificate operations detected - evaluate hybrid certificate infrastructure readiness"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: new X509Certificate2($BYTES)
          - pattern: new X509Certificate2($PATH)
          - pattern: X509Certificate2.CreateFromPem($PEM)
          - pattern: new X509Chain()
          - pattern: $CHAIN.Build($CERT)
          - pattern: new CertificateRequest($SUBJECT, $KEY, $HASH)
          - pattern: $REQUEST.CreateSelfSigned($NOT_BEFORE, $NOT_AFTER)
          - pattern: $CERT.GetPublicKey()
          - pattern: $CERT.Verify()
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "PKI infrastructure usage documented - verify certificate authorities and systems support hybrid or PQC certificates"
""",
        "test": """using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CSharpPqcPkiInfrastructure
{
    class Program
    {
        static void PkiUsage()
        {
            var cert = new X509Certificate2("cert.pem");
            var fromPem = X509Certificate2.CreateFromPemFile("cert.pem");
            var chain = new X509Chain();
            chain.Build(cert);
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=example", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var selfSigned = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            cert.GetPublicKey();
            cert.Verify();
        }
    }
}
""",
        "negative": """using System;

namespace CSharpPqcPkiInfrastructureNegative
{
    class Program
    {
        static string PemHeader()
        {
            return "-----BEGIN CERTIFICATE-----";
        }
    }
}
""",
    },
    "csharp-pqc-certificate-transparency": {
        "category": "pqc",
        "yaml": """rules:
  - id: csharp-pqc-certificate-transparency
    message: "Certificate Transparency operations detected - ensure PQC certificate support"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: $CERT.Extensions
          - pattern: new X509Extension($OID, $RAW, $CRITICAL)
          - pattern: $EXTENSION.RawData
          - pattern: X509Certificate2.CreateFromPem($PEM, $KEY_PEM)
    metadata:
      category: pqc_readiness
      cwe: CWE-295
      impact: Certificate Transparency logs must support PQC certificates
""",
        "test": """using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace CSharpPqcCertificateTransparency
{
    class Program
    {
        static void CtUsage()
        {
            var cert = new X509Certificate2("cert.pem");
            var extensions = cert.Extensions;
            var sct = extensions.Cast<X509Extension>().FirstOrDefault();
            if (sct != null)
            {
                var raw = sct.RawData;
            }
            var oid = new Oid("1.3.6.1.4.1.11129.2.4.2");
            var ext = new X509Extension(oid, new byte[] { 0x04, 0x03 }, false);
        }
    }
}
""",
        "negative": """using System;

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
""",
    },
    "csharp-pqc-elliptic-curves": {
        "category": "pqc",
        "yaml": """rules:
  - id: csharp-pqc-elliptic-curves
    message: "Elliptic curve cryptography identified - catalog for PQC migration assessment"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: ECDsa.Create($CURVE)
          - pattern: ECDsa.Create()
          - pattern: ECDiffieHellman.Create($CURVE)
          - pattern: ECCurve.NamedCurves.nistP256
          - pattern: ECCurve.NamedCurves.nistP384
          - pattern: ECCurve.NamedCurves.nistP521
          - pattern: $ECDSA.SignData($DATA, $HASH)
          - pattern: $ECDSA.VerifyData($DATA, $SIGNATURE, $HASH)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "Elliptic curve usage documented for PQC transition planning - verify system supports algorithm substitution"
""",
        "test": """using System;
using System.Security.Cryptography;
using System.Text;

namespace CSharpPqcEllipticCurves
{
    class Program
    {
        static void EllipticCurveUsage()
        {
            byte[] data = Encoding.UTF8.GetBytes("test");
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
            var p521 = ECCurve.NamedCurves.nistP521;
            var sig = ecdsa.SignData(data, HashAlgorithmName.SHA256);
            ecdsa.VerifyData(data, sig, HashAlgorithmName.SHA256);
        }
    }
}
""",
        "negative": """using System;

namespace CSharpPqcEllipticCurvesNegative
{
    class Program
    {
        static string CurveName()
        {
            return "P-256";
        }
    }
}
""",
    },
    "csharp-pqc-message-signing": {
        "category": "pqc",
        "yaml": """rules:
  - id: csharp-pqc-message-signing
    message: "Message signing operations detected - evaluate PQC signature algorithm support capability"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: $RSA.SignData($DATA, $HASH, $PADDING)
          - pattern: $RSA.VerifyData($DATA, $SIGNATURE, $HASH, $PADDING)
          - pattern: $ECDSA.SignData($DATA, $HASH)
          - pattern: $ECDSA.VerifyData($DATA, $SIGNATURE, $HASH)
          - pattern: new JsonWebSignatureHandler()
          - pattern: $JWS.CreateToken($DESCRIPTOR)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "Message signing mechanisms documented - verify signing libraries support hybrid or PQC signature algorithms"
""",
        "test": """using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CSharpPqcMessageSigning
{
    class Program
    {
        static void MessageSigning()
        {
            byte[] data = Encoding.UTF8.GetBytes("payload");
            using var rsa = RSA.Create(2048);
            var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            using var ecdsa = ECDsa.Create();
            var ecSig = ecdsa.SignData(data, HashAlgorithmName.SHA256);
            ecdsa.VerifyData(data, ecSig, HashAlgorithmName.SHA256);

            var jws = new JsonWebSignatureHandler();
            jws.CreateToken(new SecurityTokenDescriptor());
        }
    }
}
""",
        "negative": """using System;

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
""",
    },
    "csharp-pqc-config-profile-dependencies": {
        "category": "pqc",
        "yaml": """rules:
  - id: csharp-pqc-config-profile-dependencies
    message: "TLS/crypto configuration detected - verify PQC algorithm compatibility across system components"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: Environment.GetEnvironmentVariable("COMPlus_EnableDiagnostics")
          - pattern: Environment.GetEnvironmentVariable("DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER")
          - pattern: CryptoConfig.AllowOnlyFipsAlgorithms
          - pattern: new HttpClientHandler()
          - pattern: GrpcChannel.ForAddress($ADDRESS, $OPTIONS)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "Configuration may impose crypto requirements that create hard dependencies, causing system failures when PQC algorithms are enabled in mixed-version environments"
""",
        "test": """using System;
using System.Net.Http;
using System.Security.Cryptography;
using Grpc.Net.Client;

namespace CSharpPqcConfigProfileDependencies
{
    class Program
    {
        static void ConfigUsage()
        {
            var fipsEnv = Environment.GetEnvironmentVariable("COMPlus_EnableDiagnostics");
            var handlerEnv = Environment.GetEnvironmentVariable("DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER");
            var fipsOnly = CryptoConfig.AllowOnlyFipsAlgorithms;
            var handler = new HttpClientHandler();
            var channel = GrpcChannel.ForAddress("https://localhost:5001");
        }
    }
}
""",
        "negative": """using System;

namespace CSharpPqcConfigProfileDependenciesNegative
{
    class Program
    {
        static string AppName()
        {
            return "myapp";
        }
    }
}
""",
    },
    "csharp-pqc-hardcoded-cipher-dependencies": {
        "category": "pqc",
        "yaml": """rules:
  - id: csharp-pqc-hardcoded-cipher-dependencies
    message: "Hardcoded cipher suite or crypto algorithm configuration detected - may break when PQC algorithms are introduced"
    severity: WARNING
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: $HANDLER.SslProtocols = SslProtocols.Tls12
          - pattern: ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12
          - pattern: |
              $HANDLER.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11;
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "Hardcoded crypto configurations create dependencies that may break when PQC algorithms are enabled, especially in mixed-version environments"
""",
        "test": """using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;

namespace CSharpPqcHardcodedCipherDependencies
{
    class Program
    {
        static void RestrictCiphers()
        {
            var handler = new HttpClientHandler();
            handler.SslProtocols = SslProtocols.Tls12;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            handler.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11;
        }
    }
}
""",
        "negative": """using System.Net.Http;

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
""",
    },
    # --- Runtime security ---
    "csharp-tls-bypass": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: csharp-tls-bypass
    message: "TLS security bypass detected - compromises transport security"
    severity: ERROR
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: ServicePointManager.ServerCertificateValidationCallback = $CALLBACK
          - pattern: |
              ServicePointManager.ServerCertificateValidationCallback =
                delegate { return true; };
          - pattern: |
              $HANDLER.ServerCertificateCustomValidationCallback =
                ($REQUEST, $CERT, $CHAIN, $ERRORS) => true;
          - pattern: HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
          - pattern: $HANDLER.ServerCertificateCustomValidationCallback = $VALIDATOR
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: TLS bypasses eliminate transport security and enable MITM attacks
""",
        "test": """using System;
using System.Net;
using System.Net.Http;

namespace CSharpTlsBypass
{
    class Program
    {
        static void BypassTls()
        {
            ServicePointManager.ServerCertificateValidationCallback =
                delegate { return true; };

            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback =
                (request, cert, chain, errors) => true;
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }
    }
}
""",
        "negative": """using System.Net.Http;

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
""",
    },
    "csharp-tls-version-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: csharp-tls-version-override
    message: "TLS version override detected - may block TLS 1.3 or weaken transport security"
    severity: WARNING
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: SecurityProtocolType.Tls
          - pattern: SecurityProtocolType.Tls11
          - pattern: SecurityProtocolType.Tls12
          - pattern: ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12
          - pattern: $HANDLER.SslProtocols = SslProtocols.Tls
          - pattern: $HANDLER.SslProtocols = SslProtocols.Tls11
          - pattern: $HANDLER.SslProtocols = SslProtocols.Tls12
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: "TLS version restrictions may conflict with platform TLS profiles requiring TLS 1.3"
""",
        "test": """using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;

namespace CSharpTlsVersionOverride
{
    class Program
    {
        static void LimitTls()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            var handler = new HttpClientHandler();
            handler.SslProtocols = SslProtocols.Tls;
            handler.SslProtocols = SslProtocols.Tls11;
            handler.SslProtocols = SslProtocols.Tls12;
            var legacy = SecurityProtocolType.Tls11;
        }
    }
}
""",
        "negative": """using System.Net.Http;

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
""",
    },
    "csharp-certificate-validation-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: csharp-certificate-validation-override
    message: "Certificate validation override detected - breaks trust chain"
    severity: ERROR
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: |
              $HANDLER.ServerCertificateCustomValidationCallback =
                ($REQUEST, $CERT, $CHAIN, $ERRORS) => true;
          - pattern: |
              $HANDLER.ServerCertificateCustomValidationCallback =
                ($REQUEST, $CERT, $CHAIN, $ERRORS) => { return true; };
          - pattern: RemoteCertificateValidationCallback($VALIDATION)
          - pattern: new RemoteCertificateValidationCallback($VALIDATION)
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: "Certificate validation override breaks trust chain and enables MITM attacks"
""",
        "test": """using System;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace CSharpCertificateValidationOverride
{
    class Program
    {
        static bool AlwaysValid(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
        {
            return true;
        }

        static void OverrideValidation()
        {
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback =
                (request, cert, chain, errors) => true;
            handler.ServerCertificateCustomValidationCallback =
                (request, cert, chain, errors) => { return true; };
            var callback = new RemoteCertificateValidationCallback(AlwaysValid);
        }
    }
}
""",
        "negative": """using System.Net.Http;

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
""",
    },
    "csharp-http-client-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: csharp-http-client-tls-override
    message: "HTTP client with custom TLS config detected - may override platform TLS profile settings"
    severity: WARNING
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: new HttpClientHandler()
          - pattern: new HttpClient($HANDLER)
          - pattern: $HANDLER.ClientCertificates.Add($CERT)
          - pattern: $HANDLER.SslProtocols = $PROTOCOLS
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: "Custom TLS config in HTTP clients may override platform TLS profiles"
""",
        "test": """using System;
using System.Net.Http;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace CSharpHttpClientTlsOverride
{
    class Program
    {
        static void CustomClient()
        {
            var handler = new HttpClientHandler();
            handler.ClientCertificates.Add(new X509Certificate2("client.pfx"));
            handler.SslProtocols = SslProtocols.Tls12;
            var client = new HttpClient(handler);
        }
    }
}
""",
        "negative": """using System;

namespace CSharpHttpClientTlsOverrideNegative
{
    class Program
    {
        static string FetchUrl(string url)
        {
            return url;
        }
    }
}
""",
    },
    "csharp-http-server-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: csharp-http-server-tls-override
    message: "HTTP server with custom TLS config detected - may override platform TLS profile settings"
    severity: WARNING
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: new SslStream($STREAM, $LEAVE_OPEN)
          - pattern: new SslStream($STREAM, false, $VALIDATION_CALLBACK)
          - pattern: $BUILDER.UseHttps($CERT)
          - pattern: $BUILDER.UseKestrel($OPTIONS)
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: "Custom TLS config in HTTP servers may override platform TLS profiles"
""",
        "test": """using System;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace CSharpHttpServerTlsOverride
{
    class Program
    {
        static void ServeTls(Stream stream, X509Certificate2 cert, IWebHostBuilder builder)
        {
            var ssl = new SslStream(stream, false);
            var ssl2 = new SslStream(stream, leaveInnerStreamOpen: false);
            builder.UseHttps(cert);
            builder.UseKestrel(options => { });
        }
    }
}
""",
        "negative": """using System;

namespace CSharpHttpServerTlsOverrideNegative
{
    class Program
    {
        static int ListenPort(int port)
        {
            return port;
        }
    }
}
""",
    },
    "csharp-grpc-tls-credential-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: csharp-grpc-tls-credential-override
    message: "gRPC TLS credential override detected - may bypass service mesh security"
    severity: ERROR
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: ChannelCredentials.Insecure
          - pattern: GrpcChannel.ForAddress($ADDRESS, new GrpcChannelOptions { Credentials = ChannelCredentials.Insecure })
          - pattern: $OPTIONS.Credentials = ChannelCredentials.Insecure
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: "gRPC credential override bypasses service mesh security and mTLS policies"
""",
        "test": """using System;
using Grpc.Net.Client;
using Grpc.Core;

namespace CSharpGrpcTlsCredentialOverride
{
    class Program
    {
        static void InsecureGrpc()
        {
            var creds = ChannelCredentials.Insecure;
            var channel = GrpcChannel.ForAddress(
                "http://localhost:5000",
                new GrpcChannelOptions { Credentials = ChannelCredentials.Insecure });
            var options = new GrpcChannelOptions();
            options.Credentials = ChannelCredentials.Insecure;
        }
    }
}
""",
        "negative": """using System;

namespace CSharpGrpcTlsCredentialOverrideNegative
{
    class Program
    {
        static string GrpcTarget(string host, int port)
        {
            return $"{host}:{port}";
        }
    }
}
""",
    },
    "csharp-kubernetes-client-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: csharp-kubernetes-client-tls-override
    message: "Kubernetes client TLS configuration override detected"
    severity: WARNING
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: KubernetesClientConfiguration.BuildConfigFromConfigFile()
          - pattern: KubernetesClientConfiguration.IsInCluster()
          - pattern: $CONFIG.SkipTlsVerify = true
          - pattern: new KubernetesClientConfiguration()
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: "Kubernetes client TLS override can bypass cluster security policies"
""",
        "test": """using System;
using k8s;

namespace CSharpKubernetesClientTlsOverride
{
    class Program
    {
        static void K8sInsecure()
        {
            var config = KubernetesClientConfiguration.BuildConfigFromConfigFile();
            config.SkipTlsVerify = true;
            var inCluster = KubernetesClientConfiguration.IsInCluster();
            var fresh = new KubernetesClientConfiguration();
        }
    }
}
""",
        "negative": """using System;

namespace CSharpKubernetesClientTlsOverrideNegative
{
    class Program
    {
        static string ClusterName()
        {
            return "production";
        }
    }
}
""",
    },
    "csharp-service-mesh-bypass": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: csharp-service-mesh-bypass
    message: "Service mesh TLS bypass detected - communication outside mesh security"
    severity: ERROR
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: |
              $URL = "http://" + $SERVICE_IP + ":" + $PORT
              ...
              $CLIENT.GetAsync($URL)
          - pattern: |
              $URL = "http://" + $ENDPOINT
              ...
              $CLIENT.GetStringAsync($URL)
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: "Service mesh bypass eliminates mTLS protection and security observability"
""",
        "test": """using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace CSharpServiceMeshBypass
{
    class Program
    {
        static async Task MeshBypass(HttpClient client, string serviceIp, string port)
        {
            var url = "http://" + serviceIp + ":" + port;
            await client.GetAsync(url);
        }

        static async Task EndpointBypass(HttpClient client, string endpoint)
        {
            var url = "http://" + endpoint;
            await client.GetStringAsync(url);
        }
    }
}
""",
        "negative": """using System;

namespace CSharpServiceMeshBypassNegative
{
    class Program
    {
        static string MeshUrl(string host)
        {
            return $"https://{host}";
        }
    }
}
""",
    },
    "csharp-reflection-basic-usage": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: csharp-reflection-basic-usage
    message: "Basic reflection usage detected - mapping reflection landscape"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: typeof($TYPE)
          - pattern: $OBJ.GetType()
          - pattern: Type.GetType($NAME)
          - pattern: $TYPE.GetProperty($NAME)
          - pattern: $TYPE.GetField($NAME)
          - pattern: $TYPE.GetMethod($NAME)
    metadata:
      category: reflection
      cwe: CWE-200
      impact: Basic reflection usage for landscape mapping
""",
        "test": """using System;

namespace CSharpReflectionBasicUsage
{
    class Program
    {
        static void Inspect(object obj, string name)
        {
            var t = typeof(string);
            var runtime = obj.GetType();
            var loaded = Type.GetType(name);
            var prop = t.GetProperty("Length");
            var field = t.GetField("Empty");
            var method = t.GetMethod("Concat");
        }
    }
}
""",
        "negative": """using System;

namespace CSharpReflectionBasicUsageNegative
{
    class Program
    {
        static int ObjectHash(object obj)
        {
            return obj.GetHashCode();
        }
    }
}
""",
    },
    "csharp-reflection-advanced-patterns": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: csharp-reflection-advanced-patterns
    message: "Advanced reflection patterns detected - landscape mapping"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: Assembly.Load($NAME)
          - pattern: Assembly.LoadFrom($PATH)
          - pattern: Activator.CreateInstance($TYPE)
          - pattern: Activator.CreateInstance($TYPE, $ARGS)
    metadata:
      category: reflection
      cwe: CWE-20
      impact: Can bypass type safety and create security vulnerabilities
""",
        "test": """using System;
using System.Reflection;

namespace CSharpReflectionAdvancedPatterns
{
    class Program
    {
        static void AdvancedReflection(string name, string path, Type type, object[] args)
        {
            var asm = Assembly.Load(name);
            var asmFrom = Assembly.LoadFrom(path);
            var instance = Activator.CreateInstance(type);
            var withArgs = Activator.CreateInstance(type, args);
        }
    }
}
""",
        "negative": """using System;

namespace CSharpReflectionAdvancedPatternsNegative
{
    class Program
    {
        static string StaticName()
        {
            return "System.String";
        }
    }
}
""",
    },
    "csharp-reflection-structural-manipulation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: csharp-reflection-structural-manipulation
    message: "Reflection structural manipulation detected - landscape mapping"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: $PROPERTY.SetValue($OBJ, $VALUE)
          - pattern: $FIELD.SetValue($OBJ, $VALUE)
          - pattern: $PROPERTY.SetValue($OBJ, $VALUE, $INDEX)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Runtime type manipulation can bypass compile-time safety
""",
        "test": """using System;
using System.Reflection;

namespace CSharpReflectionStructuralManipulation
{
    class Program
    {
        static void Mutate(object obj, PropertyInfo property, FieldInfo field, object value)
        {
            property.SetValue(obj, value);
            field.SetValue(obj, value);
            property.SetValue(obj, value, null);
        }
    }
}
""",
        "negative": """using System;

namespace CSharpReflectionStructuralManipulationNegative
{
    class Program
    {
        static object Read(object obj, string name)
        {
            return obj.GetType().GetProperty(name)?.GetValue(obj);
        }
    }
}
""",
    },
    "csharp-reflection-type-assertion": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: csharp-reflection-type-assertion
    message: "Reflection-based type assertion detected - potential type confusion risk"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: $OBJ is $TYPE
          - pattern: $TYPE.IsAssignableFrom($OTHER)
          - pattern: $TYPE.IsInstanceOfType($OBJ)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Type assertions from reflection can lead to type confusion vulnerabilities
""",
        "test": """using System;

namespace CSharpReflectionTypeAssertion
{
    class Program
    {
        static void CheckTypes(object obj, Type type, Type other)
        {
            var isString = obj is string;
            var assignable = type.IsAssignableFrom(other);
            var instance = type.IsInstanceOfType(obj);
        }
    }
}
""",
        "negative": """using System;

namespace CSharpReflectionTypeAssertionNegative
{
    class Program
    {
        static string TypeName(object obj)
        {
            return obj.GetType().Name;
        }
    }
}
""",
    },
    "csharp-reflection-value-mutation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: csharp-reflection-value-mutation
    message: "Reflection-based value mutation detected - landscape mapping"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: $PROPERTY.SetValue($OBJ, $VALUE)
          - pattern: $FIELD.SetValue($OBJ, $VALUE)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: "Reflection-based value mutation bypasses type safety and obscures data flow"
""",
        "test": """using System.Reflection;

namespace CSharpReflectionValueMutation
{
    class Program
    {
        static void MutateValues(object obj, PropertyInfo property, FieldInfo field, object value)
        {
            property.SetValue(obj, value);
            field.SetValue(obj, value);
        }
    }
}
""",
        "negative": """using System;

namespace CSharpReflectionValueMutationNegative
{
    class Program
    {
        static object Copy(object value)
        {
            return value;
        }
    }
}
""",
    },
    "csharp-dynamic-method-invocation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: csharp-dynamic-method-invocation
    message: "Dynamic method invocation patterns detected - landscape mapping"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: $METHOD.Invoke($OBJ, $ARGS)
          - pattern: |
              $METHOD = $TYPE.GetMethod($NAME)
              ...
              $METHOD.Invoke($OBJ, $ARGS)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: "Dynamic method calls can bypass authentication, authorization, and input validation"
""",
        "test": """using System;
using System.Reflection;

namespace CSharpDynamicMethodInvocation
{
    class Program
    {
        static object CallDynamic(object obj, Type type, string name, object[] args)
        {
            var method = type.GetMethod(name);
            var direct = method.Invoke(obj, args);
            var resolved = type.GetMethod(name);
            return resolved.Invoke(obj, args);
        }
    }
}
""",
        "negative": """using System;

namespace CSharpDynamicMethodInvocationNegative
{
    class Sample
    {
        public string Run() => "ok";
    }

    class Program
    {
        static string CallDirect(Sample obj)
        {
            return obj.Run();
        }
    }
}
""",
    },
    "csharp-unsafe-pointer-operations": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: csharp-unsafe-pointer-operations
    message: "Unsafe memory operations detected - landscape mapping"
    severity: INFO
    languages:
      - csharp
    patterns:
      - pattern-either:
          - pattern: unsafe
          - pattern: fixed ($TYPE $VAR = $EXPR)
          - pattern: stackalloc $TYPE[$SIZE]
          - pattern: Marshal.AllocHGlobal($SIZE)
          - pattern: Marshal.Copy($SRC, $DEST, $START, $LENGTH)
    metadata:
      category: memory_safety
      cwe: CWE-119
      impact: Unsafe memory operations can lead to memory corruption
""",
        "test": """using System;
using System.Runtime.InteropServices;

namespace CSharpUnsafePointerOperations
{
    class Program
    {
        unsafe static void UnsafeOps(byte[] buffer, int size)
        {
            fixed (byte* ptr = buffer)
            {
                Span<byte> span = stackalloc byte[size];
                IntPtr native = Marshal.AllocHGlobal(size);
                Marshal.Copy(buffer, 0, native, size);
            }
        }
    }
}
""",
        "negative": """using System;

namespace CSharpUnsafePointerOperationsNegative
{
    class Program
    {
        static int SafeLen(byte[] data)
        {
            return data.Length;
        }
    }
}
""",
    },
}


def write_files():
    for rule_id, spec in RULES.items():
        cat = spec["category"]
        rules_dir = RULES_PQC if cat == "pqc" else RULES_RT
        rules_dir.mkdir(parents=True, exist_ok=True)
        (rules_dir / f"{rule_id}.yml").write_text(spec["yaml"])

        test_dir = TESTS / cat / rule_id
        test_dir.mkdir(parents=True, exist_ok=True)
        (test_dir / f"test_code.{EXT}").write_text(spec["test"])
        (test_dir / f"negative_cases.{EXT}").write_text(spec["negative"])


def semgrep_findings(rule_id: str, test_file: Path) -> list[dict]:
    rule_file = None
    for base in (RULES_PQC, RULES_RT):
        candidate = base / f"{rule_id}.yml"
        if candidate.exists():
            rule_file = candidate
            break
    if not rule_file:
        return []
    result = subprocess.run(
        ["semgrep", "--config", str(rule_file), "--json", str(test_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in (0, 1):
        print(f"semgrep error for {rule_id}: {result.stderr}")
        return []
    data = json.loads(result.stdout or "{}")
    return data.get("results", [])


def write_expected():
    for rule_id in RULES:
        cat = RULES[rule_id]["category"]
        test_dir = TESTS / cat / rule_id
        test_file = test_dir / f"test_code.{EXT}"
        findings = []
        for item in semgrep_findings(rule_id, test_file):
            rid = item["check_id"].split(".")[-1]
            if rid != rule_id:
                continue
            findings.append(
                {
                    "file": f"test_code.{EXT}",
                    "line": item["start"]["line"],
                    "rule_id": rule_id,
                    "message": item["extra"]["message"],
                }
            )
        findings.sort(key=lambda x: x["line"])
        lines = ["findings:"]
        for f in findings:
            lines.append(f"  - file: {f['file']}")
            lines.append(f"    line: {f['line']}")
            lines.append(f"    rule_id: {f['rule_id']}")
            msg = f["message"].replace('"', '\\"')
            lines.append(f'    message: "{msg}"')
        lines.append("")
        lines.append("no_findings:")
        lines.append(f"  - negative_cases.{EXT}")
        (test_dir / "expected.yml").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    write_files()
    write_expected()
    print(f"Generated {len(RULES)} C# rules with tests")
