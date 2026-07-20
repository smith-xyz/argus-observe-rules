#!/usr/bin/env python3
"""Generate Rust PQC and runtime-security rules with tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_PQC = ROOT / "rules/languages/rust/pqc"
RULES_RT = ROOT / "rules/languages/rust/runtime-security"
TESTS = ROOT / "tests/languages/rust"
EXT = "rs"

RULES: dict[str, dict] = {
    # --- PQC ---
    "rust-pqc-jwt-operations": {
        "category": "pqc",
        "yaml": """rules:
  - id: rust-pqc-jwt-operations
    message: JWT token operations detected - verify PQC signature algorithm support
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: jsonwebtoken::encode($HEADER, $CLAIMS, $KEY)
          - pattern: jsonwebtoken::decode($TOKEN, $KEY, $VALIDATION)
          - pattern: encode($HEADER, $CLAIMS, $KEY)
          - pattern: decode($TOKEN, $KEY, $VALIDATION)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: JWT infrastructure may need updates for PQC signature algorithms
""",
        "test": """use jsonwebtoken::{decode, encode, Header, Validation};

fn create_token(claims: serde_json::Value, key: &[u8]) -> String {
    encode(&Header::default(), &claims, key).unwrap()
}

fn parse_token(token: &str, key: &[u8]) -> serde_json::Value {
    decode(token, key, &Validation::default()).unwrap().claims
}

fn parse_with_crate(token: &str, key: &[u8]) -> serde_json::Value {
    jsonwebtoken::decode(token, key, &Validation::default())
        .unwrap()
        .claims
}
""",
        "negative": """fn build_token_string(header: &str, payload: &str) -> String {
    format!("{}.{}.sig", header, payload)
}

fn validate_format(token: &str) -> bool {
    token.matches('.').count() == 2
}
""",
    },
    "rust-pqc-jwt-rsa-ecdsa": {
        "category": "pqc",
        "yaml": """rules:
  - id: rust-pqc-jwt-rsa-ecdsa
    message: JWT with RSA/ECDSA signatures detected - assess PQC signature algorithm support readiness
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: "Header::new(Algorithm::RS256)"
          - pattern: "Header::new(Algorithm::RS384)"
          - pattern: "Header::new(Algorithm::RS512)"
          - pattern: "Header::new(Algorithm::ES256)"
          - pattern: "Header::new(Algorithm::ES384)"
          - pattern: "Header::new(Algorithm::PS256)"
          - pattern: "Validation::new(Algorithm::RS256)"
          - pattern: "Validation::new(Algorithm::ES256)"
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: JWT signature algorithms catalogued - verify JWT library supports hybrid or PQC signature methods
""",
        "test": """use jsonwebtoken::{encode, decode, Header, Validation, Algorithm};

fn sign_rs256(claims: serde_json::Value, key: &[u8]) -> String {
    let header = Header::new(Algorithm::RS256);
    encode(&header, &claims, key).unwrap()
}

fn sign_es256(claims: serde_json::Value, key: &[u8]) -> String {
    let header = Header::new(Algorithm::ES256);
    encode(&header, &claims, key).unwrap()
}

fn verify_rs256(token: &str, key: &[u8]) -> serde_json::Value {
    let validation = Validation::new(Algorithm::RS256);
    decode(token, key, &validation).unwrap().claims
}
""",
        "negative": """use jsonwebtoken::{encode, Header, Algorithm};

fn sign_hs256(claims: serde_json::Value, key: &[u8]) -> String {
    let header = Header::new(Algorithm::HS256);
    encode(&header, &claims, key).unwrap()
}
""",
    },
    "rust-pqc-oauth-jwt-saml": {
        "category": "pqc",
        "yaml": """rules:
  - id: rust-pqc-oauth-jwt-saml
    message: OAuth/SAML/OIDC operations detected - assess identity protocol PQC signature readiness
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: BasicClient::new($CLIENT_ID)
          - pattern: $CLIENT.exchange_code($CODE)
          - pattern: $CLIENT.set_auth_uri($URI)
          - pattern: CoreClient::from_provider($PROVIDER, $CLIENT_ID, $CLIENT_SECRET)
          - pattern: $CLIENT.authorize_url($...ARGS)
          - pattern: ServiceProvider::new($SETTINGS)
          - pattern: $SP.parse_response($RESPONSE)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Identity protocol usage documented - verify OAuth/SAML/OIDC libraries support hybrid or PQC signature algorithms
""",
        "test": """use oauth2::{BasicClient, ClientId, ClientSecret, AuthUrl, TokenUrl, AuthorizationCode};
use openidconnect::{CoreClient, IssuerUrl, RedirectUrl};
use saml2::ServiceProvider;

async fn oauth_flow(client_id: &str, client_secret: &str, code: AuthorizationCode) {
    let client = BasicClient::new(
        ClientId::new(client_id.to_string()),
        Some(ClientSecret::new(client_secret.to_string())),
        AuthUrl::new("https://auth.example.com/authorize".to_string()).unwrap(),
        Some(TokenUrl::new("https://auth.example.com/token".to_string()).unwrap()),
    );
    client.set_auth_uri(AuthUrl::new("https://auth.example.com/authorize".to_string()).unwrap());
    let _token = client.exchange_code(code).request_async(oauth2::reqwest::async_http_client).await;
}

async fn oidc_flow() {
    let issuer = IssuerUrl::new("https://auth.example.com".to_string()).unwrap();
    let provider = openidconnect::core::CoreProviderMetadata::new(
        issuer.clone(),
        openidconnect::core::CoreJsonWebKeySet::new(vec![]),
    );
    let _client = CoreClient::from_provider(
        provider,
        ClientId::new("id".to_string()),
        Some(ClientSecret::new("secret".to_string())),
    )
    .set_redirect_uri(RedirectUrl::new("https://app.example.com/callback".to_string()).unwrap());
}

fn saml_auth(settings: saml2::Settings) {
    let sp = ServiceProvider::new(settings);
    let _ = sp.parse_response(b"<Response/>");
}
""",
        "negative": """fn parse_bearer_token(header: &str) -> &str {
    header.strip_prefix("Bearer ").unwrap_or(header)
}
""",
    },
    "rust-pqc-ssh-client": {
        "category": "pqc",
        "yaml": """rules:
  - id: rust-pqc-ssh-client
    message: SSH client configuration detected - evaluate PQC SSH algorithm support readiness
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: ssh2::Session::new()
          - pattern: |
              $SESSION = ssh2::Session::new()
              ...
              $SESSION.set_tcp_stream($TCP)
          - pattern: $SESSION.handshake()
          - pattern: $SESSION.userauth_password($USER, $PASS)
          - pattern: $SESSION.userauth_pubkey_file($USER, $KEY, $PASS)
          - pattern: ssh2::Session::set_method_pref($METHOD, $PREFS)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: SSH client configuration documented - verify SSH library supports hybrid or PQC key exchange and authentication algorithms
""",
        "test": """use ssh2::Session;
use std::net::TcpStream;

fn ssh_connect(host: &str, port: u16, user: &str, pass: &str) -> Session {
    let tcp = TcpStream::connect(format!("{}:{}", host, port)).unwrap();
    let mut sess = Session::new().unwrap();
    sess.set_tcp_stream(tcp);
    sess.handshake().unwrap();
    sess.userauth_password(user, pass).unwrap();
    sess
}

fn ssh_pubkey(host: &str, user: &str, key_path: &str) {
    let tcp = TcpStream::connect(host).unwrap();
    let mut sess = ssh2::Session::new().unwrap();
    sess.set_tcp_stream(tcp);
    sess.handshake().unwrap();
    sess.userauth_pubkey_file(user, None, key_path, None).unwrap();
}
""",
        "negative": """fn format_ssh_command(host: &str, user: &str) -> String {
    format!("ssh {}@{}", user, host)
}
""",
    },
    "rust-pqc-ssh-server": {
        "category": "pqc",
        "yaml": """rules:
  - id: rust-pqc-ssh-server
    message: SSH server configuration detected - assess PQC SSH algorithm implementation capability
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: russh::server::Config::default()
          - pattern: russh::server::run($ADDR, $CONFIG, $HANDLER)
          - pattern: $SERVER.run_on_address($ADDR, $CONFIG)
          - pattern: ssh2::Session::channel_direct_tcpip($HOST, $PORT, $ORIG)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: SSH server configuration catalogued - verify SSH server supports hybrid host keys and PQC algorithms
""",
        "test": """use russh::server;
use std::net::SocketAddr;

struct SshHandler;

#[async_trait::async_trait]
impl server::Server for SshHandler {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        Self
    }
}

async fn start_ssh_server(addr: SocketAddr) {
    let config = russh::server::Config::default();
    let _ = server::run(addr, config, SshHandler).await;
}

fn ssh_channel(sess: &ssh2::Session, host: &str, port: u16) {
    let _ = sess.channel_direct_tcpip(host, port, "127.0.0.1", 0);
}
""",
        "negative": """fn describe_ssh_port(port: u16) -> String {
    format!("SSH listens on {}", port)
}
""",
    },
    "rust-pqc-grpc-tls": {
        "category": "pqc",
        "yaml": """rules:
  - id: rust-pqc-grpc-tls
    message: gRPC TLS configuration detected - evaluate hybrid TLS and certificate support capability
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: tonic::transport::Channel::from_static($URL)
          - pattern: tonic::transport::Channel::from_shared($URL)
          - pattern: ClientTlsConfig::new()
          - pattern: ServerTlsConfig::new()
          - pattern: $CHANNEL.tls_config($CONFIG)
          - pattern: grpcio::ChannelBuilder::new($ENV)
          - pattern: $BUILDER.secure_channel($TARGET, $CREDS)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: gRPC TLS configuration documented - verify gRPC supports hybrid certificates and PQC cipher suites
""",
        "test": """use tonic::transport::{Channel, ClientTlsConfig, ServerTlsConfig};

async fn secure_tonic_channel() {
    let tls = ClientTlsConfig::new();
    let _channel = Channel::from_static("https://example.com:443")
        .tls_config(tls)
        .unwrap()
        .connect()
        .await;
}

async fn shared_channel(url: &str) {
    let _channel = Channel::from_shared(url.to_string()).unwrap().connect().await;
}

fn server_tls() -> ServerTlsConfig {
    ServerTlsConfig::new()
}

fn grpcio_channel(env: grpcio::Environment) {
    let builder = grpcio::ChannelBuilder::new(env);
    let _ = builder.secure_channel("example.com:443", grpcio::ChannelCredentials::default());
}
""",
        "negative": """fn grpc_endpoint(host: &str, port: u16) -> String {
    format!("{}:{}", host, port)
}
""",
    },
    "rust-pqc-pki-infrastructure": {
        "category": "pqc",
        "yaml": """rules:
  - id: rust-pqc-pki-infrastructure
    message: PKI and X.509 certificate operations detected - evaluate hybrid certificate infrastructure readiness
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: rcgen::CertificateParams::default()
          - pattern: rcgen::generate_simple_self_signed($SUBJECT)
          - pattern: $PARAMS.self_signed($KEY)
          - pattern: x509_parser::parse_x509_certificate($DATA)
          - pattern: x509_parser::parse_x509_pem($DATA)
          - pattern: $CERT.public_key()
          - pattern: $CERT.validity()
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: PKI infrastructure usage documented - verify certificate authorities and systems support hybrid or PQC certificates
""",
        "test": """use rcgen::{CertificateParams, generate_simple_self_signed, KeyPair};
use x509_parser::prelude::*;

fn build_cert() {
    let params = CertificateParams::default();
    let key = KeyPair::generate().unwrap();
    let _cert = params.self_signed(&key).unwrap();
}

fn self_signed() {
    let _cert = generate_simple_self_signed(vec!["example.com".into()]).unwrap();
}

fn parse_cert(data: &[u8]) {
    let (_, cert) = parse_x509_certificate(data).unwrap();
    let _pk = cert.public_key();
    let _validity = cert.validity();
}

fn parse_pem(data: &[u8]) {
    let _ = parse_x509_pem(data);
}
""",
        "negative": """fn pem_header() -> &'static str {
    "-----BEGIN CERTIFICATE-----"
}
""",
    },
    "rust-pqc-certificate-transparency": {
        "category": "pqc",
        "yaml": """rules:
  - id: rust-pqc-certificate-transparency
    message: Certificate Transparency operations detected - ensure PQC certificate support
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: ct_client::LogClient::new($URL)
          - pattern: $CLIENT.get_sth()
          - pattern: $CLIENT.get_entries($START, $END)
          - pattern: $CLIENT.add_chain($CHAIN)
          - pattern: sct::verify_sct($CERT, $LOGS, $TIMESTAMP)
    metadata:
      category: pqc_readiness
      cwe: CWE-295
      impact: Certificate Transparency logs must support PQC certificates
""",
        "test": """use ct_client::LogClient;
use sct;

fn query_ct_log(url: &str) {
    let client = LogClient::new(url.to_string());
    let _sth = client.get_sth();
    let _entries = client.get_entries(0, 10);
}

fn submit_chain(client: &LogClient, chain: &[u8]) {
    let _ = client.add_chain(chain);
}

fn verify_sct(cert: &[u8], logs: &[sct::Log], timestamp: u64) {
    let _ = sct::verify_sct(cert, logs, timestamp);
}
""",
        "negative": """fn log_url(base: &str) -> String {
    format!("{}/ct/v1/get-sth", base)
}
""",
    },
    "rust-pqc-elliptic-curves": {
        "category": "pqc",
        "yaml": """rules:
  - id: rust-pqc-elliptic-curves
    message: Elliptic curve cryptography identified - catalog for PQC migration assessment
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: p256::ecdsa::SigningKey::random($RNG)
          - pattern: p384::ecdsa::SigningKey::random($RNG)
          - pattern: k256::ecdsa::SigningKey::random($RNG)
          - pattern: ed25519_dalek::SigningKey::generate($RNG)
          - pattern: ed25519_dalek::SigningKey::from_bytes($KEY)
          - pattern: $SIGNER.sign($DATA)
          - pattern: $VERIFIER.verify($DATA, $SIG)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Elliptic curve usage documented for PQC transition planning - verify system supports algorithm substitution
""",
        "test": """use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use p256::ecdsa::{signature::Signer as _, SigningKey as P256Key};
use rand::rngs::OsRng;

fn gen_p256_key() -> P256Key {
    P256Key::random(&mut OsRng)
}

fn gen_ed25519() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn sign_ed(key: &SigningKey, data: &[u8]) -> ed25519_dalek::Signature {
    key.sign(data)
}

fn verify_ed(key: &VerifyingKey, data: &[u8], sig: &ed25519_dalek::Signature) {
    key.verify(data, sig).unwrap();
}
""",
        "negative": """fn curve_name() -> &'static str {
    "P-256"
}
""",
    },
    "rust-pqc-message-signing": {
        "category": "pqc",
        "yaml": """rules:
  - id: rust-pqc-message-signing
    message: Message signing operations detected - evaluate PQC signature algorithm support capability
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: ring::signature::sign($ALGO, $PRIVATE_KEY, $MESSAGE)
          - pattern: ring::signature::verify($PUBLIC_KEY, $MESSAGE, $SIGNATURE)
          - pattern: rsa::RsaPrivateKey::sign($PADDING, $HASH, $DATA)
          - pattern: $SIGNING_KEY.sign($DATA)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Message signing mechanisms documented - verify signing libraries support hybrid or PQC signature algorithms
""",
        "test": """use ring::signature;
use rsa::{pkcs1v15::SigningKey, RsaPrivateKey, signature::Signer};

fn ring_sign(private_key: &[u8], message: &[u8]) {
    let algo = &signature::RSA_PKCS1_SHA256;
    let _sig = signature::sign(algo, private_key, message);
}

fn ring_verify(public_key: &signature::UnparsedPublicKey, message: &[u8], sig: &[u8]) {
    signature::verify(public_key, message, sig).unwrap();
}

fn rsa_sign(key: RsaPrivateKey, data: &[u8]) -> Vec<u8> {
    let signing_key = SigningKey::<sha2::Sha256>::new(key);
    signing_key.sign(data)
}
""",
        "negative": """fn sign_string(data: &str) -> String {
    format!("{}.signed", data)
}
""",
    },
    "rust-pqc-config-profile-dependencies": {
        "category": "pqc",
        "yaml": """rules:
  - id: rust-pqc-config-profile-dependencies
    message: TLS/crypto configuration detected - verify PQC algorithm compatibility across system components
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: std::env::var("OPENSSL_FIPS")
          - pattern: std::env::var("RUSTLS_FIPS")
          - pattern: std::env::var("FIPS_MODE")
          - pattern: rustls::ClientConfig::builder()
          - pattern: tonic::transport::Channel::from_static($URL)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Configuration may impose crypto requirements that create hard dependencies, causing system failures when PQC algorithms are enabled in mixed-version environments
""",
        "test": """use std::env;
use rustls::ClientConfig;
use tonic::transport::Channel;

fn check_fips() {
    let _ = env::var("OPENSSL_FIPS");
    let _ = env::var("RUSTLS_FIPS");
    let _ = env::var("FIPS_MODE");
}

fn tls_config() {
    let _builder = ClientConfig::builder();
}

async fn grpc_connect() {
    let _ = Channel::from_static("https://example.com:443").connect().await;
}
""",
        "negative": """fn app_name() -> &'static str {
    "myapp"
}
""",
    },
    "rust-pqc-hardcoded-cipher-dependencies": {
        "category": "pqc",
        "yaml": """rules:
  - id: rust-pqc-hardcoded-cipher-dependencies
    message: Hardcoded cipher suite or crypto algorithm configuration detected - may break when PQC algorithms are introduced
    severity: WARNING
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: |
              $CONFIG.with_cipher_suites(&[$...SUITES])
          - pattern: |
              $CONFIG.with_protocol_versions(&[rustls::ProtocolVersion::TLSv1_2])
          - pattern: "rustls::cipher_suite::TLS13_AES_256_GCM_SHA384"
          - pattern: "rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256"
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Hardcoded crypto configurations create dependencies that may break when PQC algorithms are enabled, especially in mixed-version environments
""",
        "test": """use rustls::{cipher_suite, ClientConfig, ProtocolVersion, RootCertStore};

fn restrict_ciphers() {
    let roots = RootCertStore::empty();
    let _config = ClientConfig::builder()
        .with_cipher_suites(&[cipher_suite::TLS13_AES_256_GCM_SHA384])
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
}

fn restrict_tls_version() {
    let roots = RootCertStore::empty();
    let _config = ClientConfig::builder()
        .with_safe_defaults()
        .with_protocol_versions(&[ProtocolVersion::TLSv1_2])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
}
""",
        "negative": """use rustls::ClientConfig;

fn default_config() {
    let _builder = ClientConfig::builder();
}
""",
    },
    # --- Runtime security ---
    "rust-tls-bypass": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: rust-tls-bypass
    message: TLS security bypass detected - compromises transport security
    severity: ERROR
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: $BUILDER.danger_accept_invalid_certs(true)
          - pattern: native_tls::TlsConnector::builder().danger_accept_invalid_certs(true)
          - pattern: native_tls::TlsAcceptor::builder().danger_accept_invalid_certs(true)
          - pattern: |
              reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
          - pattern: rustls::ClientConfig::builder().with_safe_defaults().dangerous()
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: TLS bypasses eliminate transport security and enable MITM attacks
""",
        "test": """use reqwest::Client;
use native_tls::{TlsConnector, TlsAcceptor};

fn bypass_reqwest() -> Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

fn bypass_native_tls() {
    let _connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let _acceptor = TlsAcceptor::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
}

fn bypass_rustls() {
    let _danger = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .dangerous();
}
""",
        "negative": """use reqwest::Client;

fn secure_client() -> Client {
    Client::builder().build().unwrap()
}
""",
    },
    "rust-tls-version-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: rust-tls-version-override
    message: TLS version override detected - may block TLS 1.3 or weaken transport security
    severity: WARNING
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: rustls::ProtocolVersion::TLSv1_2
          - pattern: rustls::ProtocolVersion::TLSv1_1
          - pattern: rustls::ProtocolVersion::TLSv1_0
          - pattern: native_tls::Protocol::Tlsv12
          - pattern: native_tls::Protocol::Tlsv11
          - pattern: native_tls::Protocol::Tlsv10
          - pattern: $BUILDER.min_protocol_version($VERSION)
          - pattern: $BUILDER.max_protocol_version($VERSION)
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: TLS version restrictions may conflict with platform TLS profiles requiring TLS 1.3
""",
        "test": """use native_tls::{Protocol, TlsConnector};
use rustls::{ClientConfig, ProtocolVersion, RootCertStore};

fn limit_rustls() {
    let roots = RootCertStore::empty();
    let _config = ClientConfig::builder()
        .with_safe_defaults()
        .with_protocol_versions(&[ProtocolVersion::TLSv1_2])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let _v1 = ProtocolVersion::TLSv1_1;
    let _v0 = ProtocolVersion::TLSv1_0;
}

fn limit_native_tls() {
    let _connector = TlsConnector::builder()
        .min_protocol_version(Some(Protocol::Tlsv12))
        .max_protocol_version(Some(Protocol::Tlsv11))
        .build()
        .unwrap();
    let _p = Protocol::Tlsv10;
}
""",
        "negative": """use rustls::ClientConfig;

fn modern_tls() {
    let _builder = ClientConfig::builder();
}
""",
    },
    "rust-certificate-validation-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: rust-certificate-validation-override
    message: Certificate validation override detected - breaks trust chain
    severity: ERROR
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: $BUILDER.danger_accept_invalid_certs(true)
          - pattern: $BUILDER.danger_accept_invalid_hostnames(true)
          - pattern: |
              $CONFIG.dangerous()
                .set_certificate_verifier($VERIFIER)
          - pattern: rustls::client::DangerousClientConfig::set_certificate_verifier($VERIFIER)
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: Certificate validation override breaks trust chain and enables MITM attacks
""",
        "test": """use reqwest::Client;

fn disable_validation() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap()
}

fn custom_verifier(verifier: std::sync::Arc<dyn rustls::client::danger::ServerCertVerifier>) {
    let _config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .dangerous()
        .set_certificate_verifier(verifier);
}
""",
        "negative": """use reqwest::Client;

fn secure_client() -> Client {
    Client::builder().build().unwrap()
}
""",
    },
    "rust-http-client-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: rust-http-client-tls-override
    message: HTTP client with custom TLS config detected - may override platform TLS profile settings
    severity: WARNING
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: reqwest::Client::builder()
          - pattern: reqwest::ClientBuilder::new()
          - pattern: hyper_util::client::legacy::Client::builder($...ARGS)
          - pattern: ureq::AgentBuilder::new()
          - pattern: isahc::HttpClient::builder()
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: Custom TLS config in HTTP clients may override platform TLS profiles
""",
        "test": """use reqwest::Client;
use ureq::AgentBuilder;

fn custom_clients() {
    let _client = reqwest::Client::builder().build().unwrap();
    let _builder = reqwest::ClientBuilder::new();
    let _agent = AgentBuilder::new().build();
    let _isahc = isahc::HttpClient::builder().build().unwrap();
}
""",
        "negative": """fn fetch_url(url: &str) -> &str {
    url
}
""",
    },
    "rust-http-server-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: rust-http-server-tls-override
    message: HTTP server with custom TLS config detected - may override platform TLS profile settings
    severity: WARNING
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: axum_server::bind_rustls($ADDR, $CONFIG)
          - pattern: axum_server::bind_rustls_acme($ADDR, $CONFIG)
          - pattern: warp::serve($FILTER).tls()
          - pattern: hyper_rustls::HttpsConnectorBuilder::new()
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: Custom TLS config in HTTP servers may override platform TLS profiles
""",
        "test": """use axum::{Router, routing::get};
use std::net::SocketAddr;

async fn serve_tls(addr: SocketAddr, config: rustls::ServerConfig) {
    let app = Router::new().route("/", get(|| async { "ok" }));
    let _ = axum_server::bind_rustls(addr, config).serve(app.into_make_service()).await;
}

fn warp_tls() {
    let routes = warp::path("health").map(|| "ok");
    let _ = warp::serve(routes).tls();
}

fn hyper_rustls_builder() {
    let _builder = hyper_rustls::HttpsConnectorBuilder::new();
}
""",
        "negative": """fn listen_port(port: u16) -> u16 {
    port
}
""",
    },
    "rust-grpc-tls-credential-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: rust-grpc-tls-credential-override
    message: gRPC TLS credential override detected - may bypass service mesh security
    severity: ERROR
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: tonic::transport::Endpoint::from_static($URL)
          - pattern: tonic::transport::Channel::from_shared($URL)
          - pattern: grpcio::ChannelBuilder::new($ENV)
          - pattern: $BUILDER.connect($TARGET)
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: gRPC credential override bypasses service mesh security and mTLS policies
""",
        "test": """use tonic::transport::{Channel, Endpoint};
use grpcio::{ChannelBuilder, Environment};

async fn insecure_grpc() {
    let _channel = Channel::from_shared("http://example.com:50051".to_string())
        .unwrap()
        .connect()
        .await;
    let _endpoint = Endpoint::from_static("http://127.0.0.1:50051");
}

fn grpcio_insecure() {
    let env = Environment::new(1);
    let builder = ChannelBuilder::new(env);
    let _ = builder.connect("127.0.0.1:50051");
}
""",
        "negative": """fn grpc_target(host: &str, port: u16) -> String {
    format!("{}:{}", host, port)
}
""",
    },
    "rust-kubernetes-client-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: rust-kubernetes-client-tls-override
    message: Kubernetes client TLS configuration override detected
    severity: WARNING
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: kube::Config::infer()
          - pattern: kube::Client::try_default()
          - pattern: $CONFIG.accept_invalid_certs = true
          - pattern: $CONFIG.insecure = true
          - pattern: kube::config::Kubeconfig::read()
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: Kubernetes client TLS override can bypass cluster security policies
""",
        "test": """use kube::{Client, Config};

async fn k8s_insecure() {
    let mut config = Config::infer().await.unwrap();
    config.accept_invalid_certs = true;
    config.insecure = true;
    let _client = Client::try_default().await.unwrap();
    let _kubeconfig = kube::config::Kubeconfig::read().unwrap();
}
""",
        "negative": """fn cluster_name() -> &'static str {
    "production"
}
""",
    },
    "rust-service-mesh-bypass": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: rust-service-mesh-bypass
    message: Service mesh TLS bypass detected - communication outside mesh security
    severity: ERROR
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: |
              $URL = format!("http://{}:{}", $SERVICE_IP, $PORT)
              ...
              reqwest::get(&$URL)
          - pattern: |
              $URL = format!("http://{}", $ENDPOINT)
              ...
              reqwest::get(&$URL)
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: Service mesh bypass eliminates mTLS protection and security observability
""",
        "test": """async fn mesh_bypass(service_ip: &str, port: u16) {
    let url = format!("http://{}:{}", service_ip, port);
    let _ = reqwest::get(&url).await;
}

async fn endpoint_bypass(endpoint: &str) {
    let url = format!("http://{}", endpoint);
    let _ = reqwest::get(&url).await;
}
""",
        "negative": """fn mesh_url(host: &str) -> String {
    format!("https://{}", host)
}
""",
    },
    "rust-reflection-basic-usage": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: rust-reflection-basic-usage
    message: Basic reflection usage detected - mapping reflection landscape
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: std::any::TypeId::of::<$T>()
          - pattern: ($OBJ as &dyn std::any::Any).type_id()
          - pattern: std::mem::size_of::<$T>()
          - pattern: std::mem::align_of::<$T>()
          - pattern: std::any::type_name::<$T>()
    metadata:
      category: reflection
      cwe: CWE-200
      impact: Basic reflection usage for landscape mapping
""",
        "test": """use std::any::{Any, TypeId};

fn inspect_type<T: 'static>() -> TypeId {
    TypeId::of::<T>()
}

fn inspect_object(obj: &dyn Any) -> TypeId {
    obj.type_id()
}

fn type_layout<T>() -> (usize, usize) {
    (std::mem::size_of::<T>(), std::mem::align_of::<T>())
}

fn type_name<T>() -> &'static str {
    std::any::type_name::<T>()
}
""",
        "negative": """fn object_ptr<T>(obj: &T) -> *const T {
    obj as *const T
}
""",
    },
    "rust-reflection-advanced-patterns": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: rust-reflection-advanced-patterns
    message: Advanced reflection patterns detected - landscape mapping
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: include!($PATH)
          - pattern: include_str!($PATH)
          - pattern: include_bytes!($PATH)
          - pattern: $ANY.downcast_ref::<$T>()
          - pattern: $ANY.downcast_mut::<$T>()
    metadata:
      category: reflection
      cwe: CWE-20
      impact: Can bypass type safety and create security vulnerabilities
""",
        "test": """use std::any::Any;

fn load_generated() {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

fn load_str(path: &str) -> &'static str {
    include_str!(path)
}

fn downcast(obj: &dyn Any) -> Option<&String> {
    obj.downcast_ref::<String>().map(|s| s)
}

fn downcast_mut(obj: &mut dyn Any) -> Option<&mut String> {
    obj.downcast_mut::<String>()
}
""",
        "negative": """fn static_module() -> &'static str {
    "json"
}
""",
    },
    "rust-reflection-structural-manipulation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: rust-reflection-structural-manipulation
    message: Reflection structural manipulation detected - landscape mapping
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: std::mem::replace(&mut $TARGET, $VALUE)
          - pattern: std::mem::swap(&mut $A, &mut $B)
          - pattern: std::mem::take(&mut $TARGET)
          - pattern: std::mem::forget($VALUE)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Runtime type manipulation can bypass compile-time safety
""",
        "test": """fn mutate<T>(target: &mut T, value: T) -> T {
    std::mem::replace(target, value)
}

fn swap_values<T>(a: &mut T, b: &mut T) {
    std::mem::swap(a, b);
}

fn take_value<T: Default>(target: &mut T) -> T {
    std::mem::take(target)
}

fn leak_value<T>(value: T) {
    std::mem::forget(value);
}
""",
        "negative": """fn read_field<T: Copy>(value: T) -> T {
    value
}
""",
    },
    "rust-reflection-type-assertion": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: rust-reflection-type-assertion
    message: Reflection-based type assertion detected - potential type confusion risk
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: $ANY.is::<$T>()
          - pattern: $ANY.downcast_ref::<$T>()
          - pattern: $ANY.downcast_mut::<$T>()
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Type assertions from reflection can lead to type confusion vulnerabilities
""",
        "test": """use std::any::Any;

fn check_type(any: &dyn Any) -> bool {
    any.is::<String>()
}

fn assert_ref(any: &dyn Any) -> Option<&i32> {
    any.downcast_ref::<i32>()
}

fn assert_mut(any: &mut dyn Any) -> Option<&mut i32> {
    any.downcast_mut::<i32>()
}
""",
        "negative": """fn type_name<T: std::any::Any>(obj: &T) -> &'static str {
    std::any::type_name::<T>()
}
""",
    },
    "rust-reflection-value-mutation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: rust-reflection-value-mutation
    message: Reflection-based value mutation detected - landscape mapping
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: std::ptr::write(&mut $TARGET, $VALUE)
          - pattern: std::mem::replace(&mut $TARGET, $VALUE)
          - pattern: unsafe { $EXPR }
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Reflection-based value mutation bypasses type safety and obscures data flow
""",
        "test": """fn mutate_ptr<T>(target: &mut T, value: T) {
    unsafe {
        std::ptr::write(target, value);
    }
}

fn mutate_replace<T>(target: &mut T, value: T) -> T {
    std::mem::replace(target, value)
}

fn unsafe_block() {
    unsafe {
        let x = 1;
        let _ = x;
    }
}
""",
        "negative": """fn copy_value<T: Clone>(value: T) -> T {
    value.clone()
}
""",
    },
    "rust-dynamic-method-invocation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: rust-dynamic-method-invocation
    message: Dynamic method invocation patterns detected - landscape mapping
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: $LIB.get::<$T>($SYMBOL)
          - pattern: libloading::Library::new($PATH)
          - pattern: |
              $FN = $LIB.get($SYMBOL)
              ...
              $FN($...ARGS)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Dynamic method calls can bypass authentication, authorization, and input validation
""",
        "test": """use libloading::{Library, Symbol};

fn call_dynamic(path: &str, symbol: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let lib = Library::new(path)?;
    let func: Symbol<unsafe extern "C" fn()> = lib.get(symbol)?;
    unsafe { func() };
    Ok(())
}

fn indirect_call(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let lib = libloading::Library::new(path)?;
    let func = lib.get::<unsafe extern "C" fn()>(b"run")?;
    unsafe { func() };
    Ok(())
}
""",
        "negative": """fn call_direct(obj: &dyn Runnable) {
    obj.run();
}

trait Runnable {
    fn run(&self);
}
""",
    },
    "rust-unsafe-pointer-operations": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: rust-unsafe-pointer-operations
    message: Unsafe memory operations detected - landscape mapping
    severity: INFO
    languages:
      - rust
    patterns:
      - pattern-either:
          - pattern: std::mem::transmute($EXPR)
          - pattern: std::ptr::read($PTR)
          - pattern: std::ptr::write($PTR, $VALUE)
          - pattern: std::slice::from_raw_parts($PTR, $LEN)
          - pattern: std::slice::from_raw_parts_mut($PTR, $LEN)
    metadata:
      category: memory_safety
      cwe: CWE-119
      impact: Unsafe memory operations can lead to memory corruption
""",
        "test": """use std::ptr;

fn unsafe_ops(buf: *const u8, len: usize) {
    unsafe {
        let _val = ptr::read(buf);
        ptr::write(buf as *mut u8, 0);
        let _slice = std::slice::from_raw_parts(buf, len);
        let _mut_slice = std::slice::from_raw_parts_mut(buf as *mut u8, len);
        let _x: u32 = std::mem::transmute(0u32);
    }
}
""",
        "negative": """fn safe_len(data: &[u8]) -> usize {
    data.len()
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
        stderr = result.stderr.strip()
        raise RuntimeError(
            f"semgrep failed for {rule_id} (exit {result.returncode}): {stderr}"
        )
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
            lines.append(f'    message: "{f["message"]}"')
        lines.append("")
        lines.append("no_findings:")
        lines.append(f"  - negative_cases.{EXT}")
        (test_dir / "expected.yml").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    write_files()
    write_expected()
    print(f"Generated {len(RULES)} Rust rules with tests")
