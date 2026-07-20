#!/usr/bin/env python3
"""Generate Java PQC and runtime-security rules with tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_PQC = ROOT / "rules/languages/java/pqc"
RULES_RT = ROOT / "rules/languages/java/runtime-security"
TESTS = ROOT / "tests/languages/java"
EXT = "java"

RULES: dict[str, dict] = {
    # --- PQC ---
    "java-pqc-jwt-operations": {
        "category": "pqc",
        "yaml": """rules:
  - id: java-pqc-jwt-operations
    message: "JWT token operations detected - verify PQC signature algorithm support"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: Jwts.builder()
          - pattern: Jwts.parser()
          - pattern: Jwts.parserBuilder()
          - pattern: $BUILDER.compact()
          - pattern: $PARSER.parseClaimsJws($TOKEN)
          - pattern: $PARSER.parseClaimsJwt($TOKEN)
          - pattern: $PARSER.parse($TOKEN)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: JWT infrastructure may need updates for PQC signature algorithms
""",
        "test": """package javapqcjwtoperations;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;

public class TestCode {
    public String createToken(Claims claims, java.security.Key key) {
        return Jwts.builder()
            .setClaims(claims)
            .signWith(key)
            .compact();
    }

    public Claims parseToken(String token, java.security.Key key) {
        return Jwts.parser()
            .setSigningKey(key)
            .parseClaimsJws(token)
            .getBody();
    }

    public Claims parseWithBuilder(String token, java.security.Key key) {
        return Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    public Object parseJwt(String token) {
        return Jwts.parser().parse(token);
    }
}
""",
        "negative": """package javapqcjwtoperations;

public class NegativeCases {
    public String buildTokenString(String header, String payload) {
        return header + "." + payload + ".sig";
    }

    public boolean validateFormat(String token) {
        return token.split("\\.").length == 3;
    }
}
""",
    },
    "java-pqc-jwt-rsa-ecdsa": {
        "category": "pqc",
        "yaml": """rules:
  - id: java-pqc-jwt-rsa-ecdsa
    message: "JWT with RSA/ECDSA signatures detected - assess PQC signature algorithm support readiness"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: SignatureAlgorithm.RS256
          - pattern: SignatureAlgorithm.RS384
          - pattern: SignatureAlgorithm.RS512
          - pattern: SignatureAlgorithm.ES256
          - pattern: SignatureAlgorithm.ES384
          - pattern: SignatureAlgorithm.ES512
          - pattern: SignatureAlgorithm.PS256
          - pattern: $BUILDER.signWith($KEY, SignatureAlgorithm.RS256)
          - pattern: $BUILDER.signWith($KEY, SignatureAlgorithm.ES256)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "JWT signature algorithms catalogued - verify JWT library supports hybrid or PQC signature methods"
""",
        "test": """package javapqcjwtrsaecdsa;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class TestCode {
    public String signRs256(java.security.Key key) {
        return Jwts.builder()
            .setSubject("user")
            .signWith(key, SignatureAlgorithm.RS256)
            .compact();
    }

    public String signEs256(java.security.Key key) {
        return Jwts.builder()
            .setSubject("user")
            .signWith(key, SignatureAlgorithm.ES256)
            .compact();
    }

    public void listAlgorithms() {
        SignatureAlgorithm rs384 = SignatureAlgorithm.RS384;
        SignatureAlgorithm es512 = SignatureAlgorithm.ES512;
        SignatureAlgorithm ps256 = SignatureAlgorithm.PS256;
    }
}
""",
        "negative": """package javapqcjwtrsaecdsa;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class NegativeCases {
    public String signHs256(java.security.Key key) {
        return Jwts.builder()
            .setSubject("user")
            .signWith(key, SignatureAlgorithm.HS256)
            .compact();
    }
}
""",
    },
    "java-pqc-oauth-jwt-saml": {
        "category": "pqc",
        "yaml": """rules:
  - id: java-pqc-oauth-jwt-saml
    message: "OAuth/SAML/OIDC operations detected - assess identity protocol PQC signature readiness"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: new OAuth2AuthorizedClientManager($REPO, $SERVICE)
          - pattern: OAuth2AuthorizeRequest.withClientRegistrationId($ID)
          - pattern: $MANAGER.authorize($REQUEST)
          - pattern: new Clients($CLIENTS)
          - pattern: new SAML2Client($CONFIG)
          - pattern: $CLIENTS.init()
          - pattern: InitializationService.initialize()
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "Identity protocol usage documented - verify OAuth/SAML/OIDC libraries support hybrid or PQC signature algorithms"
""",
        "test": """package javapqcoauthjwtsaml;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.pac4j.core.client.Clients;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.config.SAML2Configuration;
import org.opensaml.core.config.InitializationService;

public class TestCode {
    public void oauthFlow(
        ClientRegistrationRepository repo,
        OAuth2AuthorizedClientService service
    ) {
        OAuth2AuthorizedClientManager manager = new OAuth2AuthorizedClientManager(repo, service);
        OAuth2AuthorizeRequest request = OAuth2AuthorizeRequest
            .withClientRegistrationId("client-id")
            .principal("user")
            .build();
        manager.authorize(request);
    }

    public void samlFlow() throws Exception {
        InitializationService.initialize();
        SAML2Configuration config = new SAML2Configuration("idp.xml", "sp.xml", "callback");
        SAML2Client client = new SAML2Client(config);
        Clients clients = new Clients("https://app.example.com/callback", client);
        clients.init();
    }
}
""",
        "negative": """package javapqcoauthjwtsaml;

public class NegativeCases {
    public String parseBearerToken(String header) {
        return header.replace("Bearer ", "");
    }
}
""",
    },
    "java-pqc-ssh-client": {
        "category": "pqc",
        "yaml": """rules:
  - id: java-pqc-ssh-client
    message: "SSH client configuration detected - evaluate PQC SSH algorithm support readiness"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: new JSch()
          - pattern: $JSCH.getSession($USER, $HOST, $PORT)
          - pattern: $SESSION.connect()
          - pattern: $SESSION.setPassword($PASS)
          - pattern: $JSCH.addIdentity($PATH)
          - pattern: $JSCH.addIdentity($PATH, $PASSPHRASE)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "SSH client configuration documented - verify SSH library supports hybrid or PQC key exchange and authentication algorithms"
""",
        "test": """package javapqcsshclient;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

public class TestCode {
    public Session sshConnect(String host, int port, String user, String password) throws Exception {
        JSch jsch = new JSch();
        Session session = jsch.getSession(user, host, port);
        session.setPassword(password);
        session.connect();
        return session;
    }

    public void loadKey(String path, String passphrase) throws Exception {
        JSch jsch = new JSch();
        jsch.addIdentity(path);
        jsch.addIdentity(path, passphrase);
    }
}
""",
        "negative": """package javapqcsshclient;

public class NegativeCases {
    public String formatSshCommand(String host, String user) {
        return "ssh " + user + "@" + host;
    }
}
""",
    },
    "java-pqc-ssh-server": {
        "category": "pqc",
        "yaml": """rules:
  - id: java-pqc-ssh-server
    message: "SSH server configuration detected - assess PQC SSH algorithm implementation capability"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: SshServer.setUpDefaultServer()
          - pattern: $SERVER.setHost($HOST)
          - pattern: $SERVER.setPort($PORT)
          - pattern: $SERVER.start()
          - pattern: $SERVER.setKeyPairProvider($PROVIDER)
          - pattern: $SERVER.setPasswordAuthenticator($AUTH)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "SSH server configuration catalogued - verify SSH server supports hybrid host keys and PQC algorithms"
""",
        "test": """package javapqcsshserver;

import org.apache.sshd.server.SshServer;
import org.apache.sshd.common.keyprovider.KeyPairProvider;

public class TestCode {
    public SshServer startSshServer(String host, int port, KeyPairProvider provider) throws Exception {
        SshServer server = SshServer.setUpDefaultServer();
        server.setHost(host);
        server.setPort(port);
        server.setKeyPairProvider(provider);
        server.start();
        return server;
    }
}
""",
        "negative": """package javapqcsshserver;

public class NegativeCases {
    public int describeSshPort(int port) {
        return port;
    }
}
""",
    },
    "java-pqc-grpc-tls": {
        "category": "pqc",
        "yaml": """rules:
  - id: java-pqc-grpc-tls
    message: "gRPC TLS configuration detected - evaluate hybrid TLS and certificate support capability"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: ManagedChannelBuilder.forAddress($HOST, $PORT)
          - pattern: NettyChannelBuilder.forAddress($HOST, $PORT)
          - pattern: Grpc.newChannelBuilder($TARGET, $CREDS)
          - pattern: $BUILDER.useTransportSecurity()
          - pattern: $BUILDER.sslContext($CONTEXT)
          - pattern: ServerBuilder.forPort($PORT)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "gRPC TLS configuration documented - verify gRPC supports hybrid certificates and PQC cipher suites"
""",
        "test": """package javapqcgrpctls;

import io.grpc.ManagedChannelBuilder;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.Grpc;
import io.grpc.ServerBuilder;
import io.netty.handler.ssl.SslContext;

public class TestCode {
    public io.grpc.ManagedChannel secureChannel(String host, int port, SslContext sslContext) {
        return NettyChannelBuilder.forAddress(host, port)
            .sslContext(sslContext)
            .build();
    }

    public io.grpc.ManagedChannel transportSecurity(String host, int port) {
        return ManagedChannelBuilder.forAddress(host, port)
            .useTransportSecurity()
            .build();
    }

    public io.grpc.ManagedChannel grpcBuilder(String target, io.grpc.ChannelCredentials creds) {
        return Grpc.newChannelBuilder(target, creds).build();
    }

    public io.grpc.Server grpcServer(int port) {
        return ServerBuilder.forPort(port).build();
    }
}
""",
        "negative": """package javapqcgrpctls;

public class NegativeCases {
    public String grpcEndpoint(String host, int port) {
        return host + ":" + port;
    }
}
""",
    },
    "java-pqc-pki-infrastructure": {
        "category": "pqc",
        "yaml": """rules:
  - id: java-pqc-pki-infrastructure
    message: "PKI and X.509 certificate operations detected - evaluate hybrid certificate infrastructure readiness"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: CertificateFactory.getInstance("X.509")
          - pattern: $FACTORY.generateCertificate($STREAM)
          - pattern: (X509Certificate) $CERT
          - pattern: $CERT.getPublicKey()
          - pattern: $CERT.verify($PUBLIC_KEY)
          - pattern: CertPathValidator.getInstance("PKIX")
          - pattern: $VALIDATOR.validate($PATH, $PARAMS)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "PKI infrastructure usage documented - verify certificate authorities and systems support hybrid or PQC certificates"
""",
        "test": """package javapqcpkiinfrastructure;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPath;
import java.security.cert.PKIXParameters;

public class TestCode {
    public X509Certificate loadCert(InputStream stream) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(stream);
    }

    public void verifyCert(X509Certificate cert, java.security.PublicKey issuerKey) throws Exception {
        cert.getPublicKey();
        cert.verify(issuerKey);
    }

    public void validatePath(CertPath path, PKIXParameters params) throws Exception {
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        validator.validate(path, params);
    }
}
""",
        "negative": """package javapqcpkiinfrastructure;

public class NegativeCases {
    public String pemHeader() {
        return "-----BEGIN CERTIFICATE-----";
    }
}
""",
    },
    "java-pqc-certificate-transparency": {
        "category": "pqc",
        "yaml": """rules:
  - id: java-pqc-certificate-transparency
    message: "Certificate Transparency operations detected - ensure PQC certificate support"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: $CERT.getExtensionValue("1.3.6.1.4.1.11129.2.4.2")
          - pattern: new CTLogClient($URL)
          - pattern: $CLIENT.getSignedTreeHead()
          - pattern: $CLIENT.getEntries($START, $END)
          - pattern: $CLIENT.addCertificateChain($CHAIN)
    metadata:
      category: pqc_readiness
      cwe: CWE-295
      impact: Certificate Transparency logs must support PQC certificates
""",
        "test": """package javapqccertificatetransparency;

import java.security.cert.X509Certificate;
import org.certificatetransparency.ctlog.CTLogClient;

public class TestCode {
    public byte[] readSctExtension(X509Certificate cert) {
        return cert.getExtensionValue("1.3.6.1.4.1.11129.2.4.2");
    }

    public void queryCtLog(String url) throws Exception {
        CTLogClient client = new CTLogClient(url);
        client.getSignedTreeHead();
        client.getEntries(0, 10);
        client.addCertificateChain(new byte[0]);
    }
}
""",
        "negative": """package javapqccertificatetransparency;

public class NegativeCases {
    public String logUrl(String base) {
        return base + "/ct/v1/get-sth";
    }
}
""",
    },
    "java-pqc-elliptic-curves": {
        "category": "pqc",
        "yaml": """rules:
  - id: java-pqc-elliptic-curves
    message: "Elliptic curve cryptography identified - catalog for PQC migration assessment"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: KeyPairGenerator.getInstance("EC")
          - pattern: new ECGenParameterSpec("secp256r1")
          - pattern: new ECGenParameterSpec("secp384r1")
          - pattern: new ECGenParameterSpec("secp521r1")
          - pattern: KeyPairGenerator.getInstance("Ed25519")
          - pattern: KeyPairGenerator.getInstance("Ed448")
          - pattern: $SIGNATURE.update($DATA)
          - pattern: $SIGNATURE.sign()
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "Elliptic curve usage documented for PQC transition planning - verify system supports algorithm substitution"
""",
        "test": """package javapqcellipticcurves;

import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.security.Signature;

public class TestCode {
    public void genEcKey() throws Exception {
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp256r1"));
        ec.initialize(new ECGenParameterSpec("secp384r1"));
        ec.initialize(new ECGenParameterSpec("secp521r1"));
    }

    public void genEdKeys() throws Exception {
        KeyPairGenerator ed25519 = KeyPairGenerator.getInstance("Ed25519");
        KeyPairGenerator ed448 = KeyPairGenerator.getInstance("Ed448");
    }

    public byte[] signData(Signature signature, byte[] data) throws Exception {
        signature.update(data);
        return signature.sign();
    }
}
""",
        "negative": """package javapqcellipticcurves;

public class NegativeCases {
    public String curveName() {
        return "P-256";
    }
}
""",
    },
    "java-pqc-message-signing": {
        "category": "pqc",
        "yaml": """rules:
  - id: java-pqc-message-signing
    message: "Message signing operations detected - evaluate PQC signature algorithm support capability"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: Signature.getInstance("SHA256withRSA")
          - pattern: Signature.getInstance("SHA384withRSA")
          - pattern: Signature.getInstance("SHA512withRSA")
          - pattern: Signature.getInstance("SHA256withECDSA")
          - pattern: Signature.getInstance("SHA384withECDSA")
          - pattern: Signature.getInstance("Ed25519")
          - pattern: new JWSObject($HEADER, $PAYLOAD)
          - pattern: $JWS.sign($SIGNER)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "Message signing mechanisms documented - verify signing libraries support hybrid or PQC signature algorithms"
""",
        "test": """package javapqcmessagesigning;

import java.security.Signature;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;

public class TestCode {
    public void rsaSign(byte[] data) throws Exception {
        Signature sha256rsa = Signature.getInstance("SHA256withRSA");
        Signature sha384rsa = Signature.getInstance("SHA384withRSA");
        Signature sha512rsa = Signature.getInstance("SHA512withRSA");
        sha256rsa.update(data);
        sha256rsa.sign();
    }

    public void ecSign(byte[] data) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        Signature ed25519 = Signature.getInstance("Ed25519");
        ecdsa.update(data);
        ecdsa.sign();
    }

    public void jwsSign(java.security.interfaces.RSAPrivateKey key) throws Exception {
        JWSObject jws = new JWSObject(new JWSHeader(com.nimbusds.jose.JWSAlgorithm.RS256), new Payload("data"));
        jws.sign(new RSASSASigner(key));
    }
}
""",
        "negative": """package javapqcmessagesigning;

public class NegativeCases {
    public String signString(String data) {
        return data + ".signed";
    }
}
""",
    },
    "java-pqc-config-profile-dependencies": {
        "category": "pqc",
        "yaml": """rules:
  - id: java-pqc-config-profile-dependencies
    message: "TLS/crypto configuration detected - verify PQC algorithm compatibility across system components"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: System.getenv("FIPS_MODE")
          - pattern: System.getenv("JAVA_FIPS")
          - pattern: System.getenv("org.bouncycastle.fips.approved_only")
          - pattern: SSLContext.getInstance("TLS")
          - pattern: ManagedChannelBuilder.forAddress($HOST, $PORT)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "Configuration may impose crypto requirements that create hard dependencies, causing system failures when PQC algorithms are enabled in mixed-version environments"
""",
        "test": """package javapqcconfigprofiledependencies;

import javax.net.ssl.SSLContext;
import io.grpc.ManagedChannelBuilder;

public class TestCode {
    public void checkFips() {
        System.getenv("FIPS_MODE");
        System.getenv("JAVA_FIPS");
        System.getenv("org.bouncycastle.fips.approved_only");
    }

    public SSLContext tlsContext() throws Exception {
        return SSLContext.getInstance("TLS");
    }

    public io.grpc.ManagedChannel grpcConnect(String host, int port) {
        return ManagedChannelBuilder.forAddress(host, port).build();
    }
}
""",
        "negative": """package javapqcconfigprofiledependencies;

public class NegativeCases {
    public String appName() {
        return "myapp";
    }
}
""",
    },
    "java-pqc-hardcoded-cipher-dependencies": {
        "category": "pqc",
        "yaml": """rules:
  - id: java-pqc-hardcoded-cipher-dependencies
    message: "Hardcoded cipher suite or crypto algorithm configuration detected - may break when PQC algorithms are introduced"
    severity: WARNING
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: $SOCKET.setEnabledCipherSuites($SUITES)
          - pattern: $PARAMS.setCipherSuites($SUITES)
          - pattern: $SOCKET.setEnabledProtocols($PROTOCOLS)
          - pattern: System.setProperty("jdk.tls.client.protocols", "TLSv1.2")
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: "Hardcoded crypto configurations create dependencies that may break when PQC algorithms are enabled, especially in mixed-version environments"
""",
        "test": """package javapqchardcodedcipherdependencies;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLParameters;

public class TestCode {
    public void restrictCiphers(SSLSocket socket, SSLParameters params) {
        socket.setEnabledCipherSuites(new String[] {"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"});
        params.setCipherSuites(new String[] {"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"});
        socket.setEnabledProtocols(new String[] {"TLSv1.2"});
        System.setProperty("jdk.tls.client.protocols", "TLSv1.2");
    }
}
""",
        "negative": """package javapqchardcodedcipherdependencies;

import javax.net.ssl.SSLContext;

public class NegativeCases {
    public SSLContext defaultContext() throws Exception {
        return SSLContext.getInstance("Default");
    }
}
""",
    },
    # --- Runtime security ---
    "java-tls-bypass": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: java-tls-bypass
    message: "TLS security bypass detected - compromises transport security"
    severity: ERROR
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: HttpsURLConnection.setDefaultHostnameVerifier($VERIFIER)
          - pattern: SSLContext.init($KEY, $TRUST_ALL, $RANDOM)
          - pattern: new OkHttpClient.Builder().hostnameVerifier($VERIFIER)
          - pattern: $BUILDER.hostnameVerifier($VERIFIER)
          - pattern: TrustAllStrategy
          - pattern: NoopHostnameVerifier.INSTANCE
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: TLS bypasses eliminate transport security and enable MITM attacks
""",
        "test": """package javatlsbypass;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import okhttp3.OkHttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;

public class TestCode {
    public void bypassHostnameVerifier() {
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
    }

    public SSLContext bypassSslContext() throws Exception {
        TrustManager[] trustAll = new TrustManager[] {
            new X509TrustManager() {
                public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
            }
        };
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trustAll, new java.security.SecureRandom());
        return context;
    }

    public OkHttpClient bypassOkHttp() {
        return new OkHttpClient.Builder()
            .hostnameVerifier((hostname, session) -> true)
            .build();
    }

    public void apacheBypass() {
        NoopHostnameVerifier.INSTANCE.verify("host", null);
        TrustAllStrategy.INSTANCE;
    }
}
""",
        "negative": """package javatlsbypass;

import javax.net.ssl.SSLContext;

public class NegativeCases {
    public SSLContext secureContext() throws Exception {
        return SSLContext.getDefault();
    }
}
""",
    },
    "java-tls-version-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: java-tls-version-override
    message: "TLS version override detected - may block TLS 1.3 or weaken transport security"
    severity: WARNING
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: SSLContext.getInstance("TLSv1")
          - pattern: SSLContext.getInstance("TLSv1.1")
          - pattern: SSLContext.getInstance("TLSv1.2")
          - pattern: $SOCKET.setEnabledProtocols($PROTOCOLS)
          - pattern: System.setProperty("jdk.tls.client.protocols", "TLSv1.2")
          - pattern: System.setProperty("https.protocols", "TLSv1.2")
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: "TLS version restrictions may conflict with platform TLS profiles requiring TLS 1.3"
""",
        "test": """package javatlsversionoverride;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

public class TestCode {
    public void limitTls() throws Exception {
        SSLContext tls1 = SSLContext.getInstance("TLSv1");
        SSLContext tls11 = SSLContext.getInstance("TLSv1.1");
        SSLContext tls12 = SSLContext.getInstance("TLSv1.2");
        System.setProperty("jdk.tls.client.protocols", "TLSv1.2");
        System.setProperty("https.protocols", "TLSv1.2");
    }

    public void socketProtocols(SSLSocket socket) {
        socket.setEnabledProtocols(new String[] {"TLSv1.2"});
    }
}
""",
        "negative": """package javatlsversionoverride;

import javax.net.ssl.SSLContext;

public class NegativeCases {
    public SSLContext modernTls() throws Exception {
        return SSLContext.getDefault();
    }
}
""",
    },
    "java-certificate-validation-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: java-certificate-validation-override
    message: "Certificate validation override detected - breaks trust chain"
    severity: ERROR
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: HttpsURLConnection.setDefaultHostnameVerifier($VERIFIER)
          - pattern: $CONNECTION.setHostnameVerifier($VERIFIER)
          - pattern: $CLIENT.setSSLHostnameVerifier($VERIFIER)
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: "Certificate validation override breaks trust chain and enables MITM attacks"
""",
        "test": """package javacertificatevalidationoverride;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

public class TestCode {
    public void overrideValidation() {
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

        HostnameVerifier verifier = new HostnameVerifier() {
            public boolean verify(String hostname, javax.net.ssl.SSLSession session) {
                return true;
            }
        };

        CloseableHttpClient client = HttpClients.custom()
            .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
            .build();
    }
}
""",
        "negative": """package javacertificatevalidationoverride;

import javax.net.ssl.HttpsURLConnection;

public class NegativeCases {
    public void secureDefaults() {
        HttpsURLConnection.getDefaultHostnameVerifier();
    }
}
""",
    },
    "java-http-client-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: java-http-client-tls-override
    message: "HTTP client with custom TLS config detected - may override platform TLS profile settings"
    severity: WARNING
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: new OkHttpClient.Builder()
          - pattern: HttpClient.newBuilder()
          - pattern: HttpClients.custom()
          - pattern: new RestTemplate($FACTORY)
          - pattern: $BUILDER.sslSocketFactory($FACTORY, $TRUST)
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: "Custom TLS config in HTTP clients may override platform TLS profiles"
""",
        "test": """package javahttpclienttlsoverride;

import java.net.http.HttpClient;
import okhttp3.OkHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

public class TestCode {
    public void customClients(javax.net.ssl.SSLSocketFactory factory, javax.net.ssl.X509TrustManager trust) {
        OkHttpClient ok = new OkHttpClient.Builder()
            .sslSocketFactory(factory, trust)
            .build();
        HttpClient jdk = HttpClient.newBuilder().build();
        HttpClients.custom().build();
        RestTemplate rest = new RestTemplate(new HttpComponentsClientHttpRequestFactory());
    }
}
""",
        "negative": """package javahttpclienttlsoverride;

public class NegativeCases {
    public String fetchUrl(String url) {
        return url;
    }
}
""",
    },
    "java-http-server-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: java-http-server-tls-override
    message: "HTTP server with custom TLS config detected - may override platform TLS profile settings"
    severity: WARNING
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: SSLServerSocketFactory.getDefault()
          - pattern: HttpsServer.create($CONTEXT, $PORT)
          - pattern: $SERVER.setHttpsConfigurator($CONFIG)
          - pattern: $BUILDER.sslContext($CONTEXT)
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: "Custom TLS config in HTTP servers may override platform TLS profiles"
""",
        "test": """package javahttpservertlsoverride;

import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpsConfigurator;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import io.grpc.netty.NettyServerBuilder;

public class TestCode {
    public void serveTls(SSLContext context, int port) throws Exception {
        SSLServerSocketFactory factory = SSLServerSocketFactory.getDefault();
        HttpsServer server = HttpsServer.create(new java.net.InetSocketAddress(port), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(context));
        NettyServerBuilder.forPort(port).sslContext(null);
    }
}
""",
        "negative": """package javahttpservertlsoverride;

public class NegativeCases {
    public int listenPort(int port) {
        return port;
    }
}
""",
    },
    "java-grpc-tls-credential-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: java-grpc-tls-credential-override
    message: "gRPC TLS credential override detected - may bypass service mesh security"
    severity: ERROR
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: ManagedChannelBuilder.forAddress($HOST, $PORT).usePlaintext()
          - pattern: $BUILDER.usePlaintext()
          - pattern: InsecureChannelCredentials.create()
          - pattern: Grpc.newChannelBuilder($TARGET, InsecureChannelCredentials.create())
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: "gRPC credential override bypasses service mesh security and mTLS policies"
""",
        "test": """package javagrpctlscredentialoverride;

import io.grpc.ManagedChannelBuilder;
import io.grpc.Grpc;
import io.grpc.InsecureChannelCredentials;

public class TestCode {
    public io.grpc.ManagedChannel insecureGrpc(String host, int port) {
        return ManagedChannelBuilder.forAddress(host, port).usePlaintext().build();
    }

    public io.grpc.ManagedChannel insecureBuilder(String target) {
        return Grpc.newChannelBuilder(target, InsecureChannelCredentials.create()).build();
    }

    public void plainBuilder(ManagedChannelBuilder<?> builder) {
        builder.usePlaintext();
    }
}
""",
        "negative": """package javagrpctlscredentialoverride;

public class NegativeCases {
    public String grpcTarget(String host, int port) {
        return host + ":" + port;
    }
}
""",
    },
    "java-kubernetes-client-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: java-kubernetes-client-tls-override
    message: "Kubernetes client TLS configuration override detected"
    severity: WARNING
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: Config.fromConfig($PATH)
          - pattern: Config.defaultClient()
          - pattern: $CLIENT.setVerifyingSsl(false)
          - pattern: Configuration.setDefaultApiClient($CLIENT)
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: "Kubernetes client TLS override can bypass cluster security policies"
""",
        "test": """package javakubernetesclienttlsoverride;

import io.kubernetes.client.openapi.Configuration;
import io.kubernetes.client.util.Config;
import io.kubernetes.client.openapi.ApiClient;

public class TestCode {
    public ApiClient k8sInsecure() throws Exception {
        ApiClient client = Config.fromConfig("kubeconfig");
        client.setVerifyingSsl(false);
        Configuration.setDefaultApiClient(client);
        return Config.defaultClient();
    }
}
""",
        "negative": """package javakubernetesclienttlsoverride;

public class NegativeCases {
    public String clusterName() {
        return "production";
    }
}
""",
    },
    "java-service-mesh-bypass": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: java-service-mesh-bypass
    message: "Service mesh TLS bypass detected - communication outside mesh security"
    severity: ERROR
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: '"http://" + $SERVICE_IP + ":" + $PORT'
          - pattern: '"http://" + $ENDPOINT'
          - pattern: $CLIENT.send($REQUEST, $HANDLER)
          - pattern: $CLIENT.execute($GET)
          - pattern: $CLIENT.execute(new HttpGet($URL))
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: "Service mesh bypass eliminates mTLS protection and security observability"
""",
        "test": """package javaservicemeshbypass;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

public class TestCode {
    public void meshBypass(HttpClient client, String serviceIp, String port) throws Exception {
        String url = "http://" + serviceIp + ":" + port;
        HttpRequest request = HttpRequest.newBuilder(java.net.URI.create(url)).build();
        java.net.http.HttpResponse.BodyHandler<String> handler = HttpResponse.BodyHandlers.ofString();
        client.send(request, handler);
    }

    public void endpointBypass(CloseableHttpClient client, String endpoint) throws Exception {
        String url = "http://" + endpoint;
        HttpGet get = new HttpGet(url);
        client.execute(get);
    }
}
""",
        "negative": """package javaservicemeshbypass;

public class NegativeCases {
    public String meshUrl(String host) {
        return "https://" + host;
    }
}
""",
    },
    "java-reflection-basic-usage": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: java-reflection-basic-usage
    message: "Basic reflection usage detected - mapping reflection landscape"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: $OBJ.getClass()
          - pattern: Class.forName($NAME)
          - pattern: $CLASS.getDeclaredMethod($NAME, $...ARGS)
          - pattern: $CLASS.getField($NAME)
          - pattern: $CLASS.getDeclaredField($NAME)
    metadata:
      category: reflection
      cwe: CWE-200
      impact: Basic reflection usage for landscape mapping
""",
        "test": """package javareflectionbasicusage;

public class TestCode {
    public void inspect(Object obj, String name) throws Exception {
        Class<?> runtime = obj.getClass();
        Class<?> loaded = Class.forName(name);
        java.lang.reflect.Method method = loaded.getDeclaredMethod("run");
        java.lang.reflect.Field field = loaded.getField("value");
        java.lang.reflect.Field declared = loaded.getDeclaredField("secret");
    }
}
""",
        "negative": """package javareflectionbasicusage;

public class NegativeCases {
    public int objectHashCode(Object obj) {
        return obj.hashCode();
    }
}
""",
    },
    "java-reflection-advanced-patterns": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: java-reflection-advanced-patterns
    message: "Advanced reflection patterns detected - landscape mapping"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: $LOADER.loadClass($NAME)
          - pattern: Class.forName($NAME, $INIT, $LOADER)
          - pattern: Proxy.newProxyInstance($LOADER, $INTERFACES, $HANDLER)
          - pattern: $METHOD.invoke($OBJ, $ARGS)
    metadata:
      category: reflection
      cwe: CWE-20
      impact: Can bypass type safety and create security vulnerabilities
""",
        "test": """package javareflectionadvancedpatterns;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public class TestCode {
    public Object advancedReflection(ClassLoader loader, String name, Object obj, Object[] args)
        throws Exception {
        Class<?> loaded = loader.loadClass(name);
        Class<?> initialized = Class.forName(name, true, loader);
        Object proxy = Proxy.newProxyInstance(
            loader,
            new Class<?>[] { Runnable.class },
            (p, method, a) -> null
        );
        Method method = loaded.getMethod("run");
        return method.invoke(obj, args);
    }
}
""",
        "negative": """package javareflectionadvancedpatterns;

public class NegativeCases {
    public String staticName() {
        return "java.lang.String";
    }
}
""",
    },
    "java-reflection-structural-manipulation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: java-reflection-structural-manipulation
    message: "Reflection structural manipulation detected - landscape mapping"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: $FIELD.setAccessible(true)
          - pattern: $FIELD.set($OBJ, $VALUE)
          - pattern: $METHOD.setAccessible(true)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Runtime type manipulation can bypass compile-time safety
""",
        "test": """package javareflectionstructuralmanipulation;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class TestCode {
    public void mutate(Object obj, Field field, Method method, Object value) throws Exception {
        field.setAccessible(true);
        field.set(obj, value);
        method.setAccessible(true);
    }
}
""",
        "negative": """package javareflectionstructuralmanipulation;

public class NegativeCases {
    public Object read(Object obj, String name) throws Exception {
        return obj.getClass().getField(name).get(obj);
    }
}
""",
    },
    "java-reflection-type-assertion": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: java-reflection-type-assertion
    message: "Reflection-based type assertion detected - potential type confusion risk"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: $OBJ instanceof $TYPE
          - pattern: $CLASS.isAssignableFrom($OTHER)
          - pattern: $CLASS.isInstance($OBJ)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Type assertions from reflection can lead to type confusion vulnerabilities
""",
        "test": """package javareflectiontypeassertion;

public class TestCode {
    public void checkTypes(Object obj, Class<?> type, Class<?> other) {
        boolean isString = obj instanceof String;
        boolean assignable = type.isAssignableFrom(other);
        boolean instance = type.isInstance(obj);
    }
}
""",
        "negative": """package javareflectiontypeassertion;

public class NegativeCases {
    public String typeName(Object obj) {
        return obj.getClass().getName();
    }
}
""",
    },
    "java-reflection-value-mutation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: java-reflection-value-mutation
    message: "Reflection-based value mutation detected - landscape mapping"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: $FIELD.set($OBJ, $VALUE)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: "Reflection-based value mutation bypasses type safety and obscures data flow"
""",
        "test": """package javareflectionvaluemutation;

import java.lang.reflect.Field;

public class TestCode {
    public void mutateValues(Object obj, Field field, Object value) throws Exception {
        field.set(obj, value);
    }
}
""",
        "negative": """package javareflectionvaluemutation;

public class NegativeCases {
    public Object copyValue(Object value) {
        return value;
    }
}
""",
    },
    "java-dynamic-method-invocation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: java-dynamic-method-invocation
    message: "Dynamic method invocation patterns detected - landscape mapping"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: $METHOD.invoke($OBJ, $ARGS)
          - pattern: $CLASS.getMethod($NAME).invoke($OBJ, $ARGS)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: "Dynamic method calls can bypass authentication, authorization, and input validation"
""",
        "test": """package javaynamicmethodinvocation;

import java.lang.reflect.Method;

public class TestCode {
    public Object callDynamic(Object obj, Class<?> clazz, String name, Object[] args)
        throws Exception {
        Object direct = clazz.getMethod(name).invoke(obj, args);
        Method method = clazz.getMethod(name);
        return method.invoke(obj, args);
    }
}
""",
        "negative": """package javaynamicmethodinvocation;

public class NegativeCases {
    static class Sample {
        public String run() {
            return "ok";
        }
    }

    public String callDirect(Sample obj) {
        return obj.run();
    }
}
""",
    },
    "java-unsafe-pointer-operations": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: java-unsafe-pointer-operations
    message: "Unsafe memory operations detected - landscape mapping"
    severity: INFO
    languages:
      - java
    patterns:
      - pattern-either:
          - pattern: sun.misc.Unsafe.getUnsafe()
          - pattern: $UNSAFE.allocateMemory($SIZE)
          - pattern: $UNSAFE.copyMemory($SRC, $DEST, $SIZE)
          - pattern: ByteBuffer.allocateDirect($SIZE)
          - pattern: $BUFFER.getLong($INDEX)
    metadata:
      category: memory_safety
      cwe: CWE-119
      impact: Unsafe memory operations can lead to memory corruption
""",
        "test": """package javaunsafepointeroperations;

import java.nio.ByteBuffer;
import sun.misc.Unsafe;

public class TestCode {
    public void unsafeOps(long size) throws Exception {
        Unsafe unsafe = Unsafe.getUnsafe();
        long address = unsafe.allocateMemory(size);
        unsafe.copyMemory(null, address, null, address, size);
        ByteBuffer buffer = ByteBuffer.allocateDirect((int) size);
        buffer.getLong(0);
    }
}
""",
        "negative": """package javaunsafepointeroperations;

public class NegativeCases {
    public int safeLen(byte[] data) {
        return data.length;
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
    env = {
        **subprocess.os.environ,
        "SEMGREP_LOG_FILE": str(ROOT / ".semgrep.log"),
        "SEMGREP_VERSION_CACHE_PATH": str(ROOT / ".semgrep_version_cache"),
        "SEMGREP_SEND_METRICS": "off",
    }
    result = subprocess.run(
        ["semgrep", "--config", str(rule_file), "--json", str(test_file)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    if not result.stdout.strip():
        print(f"semgrep error for {rule_id}: {result.stderr}")
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"semgrep JSON error for {rule_id}: {result.stderr}")
        return []
    if result.returncode not in (0, 1) and not data.get("results"):
        print(f"semgrep error for {rule_id}: {result.stderr}")
        return []
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
    print(f"Generated {len(RULES)} Java rules with tests")
