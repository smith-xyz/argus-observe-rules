#!/usr/bin/env python3
"""Generate C++ PQC and runtime-security rules with tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_PQC = ROOT / "rules/languages/cpp/pqc"
RULES_RT = ROOT / "rules/languages/cpp/runtime-security"
TESTS = ROOT / "tests/languages/cpp"
EXT = "cpp"

RULES: dict[str, dict] = {
    # --- PQC ---
    "cpp-pqc-jwt-operations": {
        "category": "pqc",
        "yaml": """rules:
  - id: cpp-pqc-jwt-operations
    message: JWT token operations detected - verify PQC signature algorithm support
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: jwt::create()
          - pattern: jwt::decode($TOKEN)
          - pattern: $TOKEN.sign($ALGORITHM)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: JWT infrastructure may need updates for PQC signature algorithms
""",
        "test": """#include <jwt-cpp/jwt.h>
#include <string>

void create_token() {
    auto token = jwt::create().set_payload_claim("sub", jwt::claim(std::string("user")));
    token.sign(jwt::algorithm::hs256{"secret"});
}

void parse_token() {
    auto decoded = jwt::decode("header.payload.sig");
}
""",
        "negative": """#include <string>

std::string build_token(const std::string& header, const std::string& payload) {
    return header + "." + payload + ".sig";
}
""",
    },
    "cpp-pqc-jwt-rsa-ecdsa": {
        "category": "pqc",
        "yaml": """rules:
  - id: cpp-pqc-jwt-rsa-ecdsa
    message: JWT with RSA/ECDSA signatures detected - assess PQC signature algorithm support readiness
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: '$TOKEN.set_algorithm("RS256")'
          - pattern: '$TOKEN.set_algorithm("RS384")'
          - pattern: '$TOKEN.set_algorithm("RS512")'
          - pattern: '$TOKEN.set_algorithm("ES256")'
          - pattern: '$TOKEN.set_algorithm("ES384")'
          - pattern: '$TOKEN.set_algorithm("ES512")'
          - pattern: jwt::algorithm::rs256($KEY)
          - pattern: jwt::algorithm::es256($KEY)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: JWT signature algorithms catalogued - verify JWT library supports hybrid or PQC signature methods
""",
        "test": """#include <jwt-cpp/jwt.h>
#include <string>

void sign_rs256() {
    auto token = jwt::create().set_algorithm("RS256");
    token.sign(jwt::algorithm::rs256("", "", "", ""));
}

void sign_es256() {
    auto token = jwt::create().set_algorithm("ES256");
    token.sign(jwt::algorithm::es256("", "", "", ""));
}
""",
        "negative": """#include <jwt-cpp/jwt.h>

void sign_hs256() {
    auto token = jwt::create().set_algorithm("HS256");
}
""",
    },
    "cpp-pqc-oauth-jwt-saml": {
        "category": "pqc",
        "yaml": """rules:
  - id: cpp-pqc-oauth-jwt-saml
    message: OAuth/SAML/OIDC operations detected - assess identity protocol PQC signature readiness
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: "curl_easy_setopt($CURL, CURLOPT_XOAUTH2_BEARER, $TOKEN)"
          - pattern: lasso_login_new($PROVIDER)
          - pattern: lasso_login_init_auth($LOGIN)
          - pattern: lasso_login_process_auth($LOGIN, $REQUEST)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Identity protocol usage documented - verify OAuth/SAML/OIDC libraries support hybrid or PQC signature algorithms
""",
        "test": """#include <curl/curl.h>
#include <lasso/login.h>

void oauth_bearer(CURL *curl, const char *token) {
    curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, token);
}

void saml_flow() {
    LassoLogin *login = lasso_login_new(nullptr);
    lasso_login_init_auth(login);
    lasso_login_process_auth(login, nullptr);
}
""",
        "negative": """const char *parse_bearer(const char *header) {
    return header;
}
""",
    },
    "cpp-pqc-ssh-client": {
        "category": "pqc",
        "yaml": """rules:
  - id: cpp-pqc-ssh-client
    message: SSH client configuration detected - evaluate PQC SSH algorithm support readiness
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: ssh_new()
          - pattern: |
              $SESSION = ssh_new()
              ...
              ssh_connect($SESSION)
          - pattern: ssh_options_set($SESSION, SSH_OPTIONS_HOST, $HOST)
          - pattern: ssh_userauth_publickey_auto($SESSION, $USER, $KEY)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: SSH client configuration documented - verify SSH library supports hybrid or PQC key exchange and authentication algorithms
""",
        "test": """#include <libssh/libssh.h>

void ssh_client(const char *host) {
    ssh_session session = ssh_new();
    ssh_options_set(session, SSH_OPTIONS_HOST, host);
    ssh_connect(session);
    ssh_userauth_publickey_auto(session, nullptr, nullptr);
}
""",
        "negative": """const char *ssh_command(const char *host) {
    return "ssh";
}
""",
    },
    "cpp-pqc-ssh-server": {
        "category": "pqc",
        "yaml": """rules:
  - id: cpp-pqc-ssh-server
    message: SSH server configuration detected - assess PQC SSH algorithm implementation capability
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: ssh_bind_new()
          - pattern: |
              $BIND = ssh_bind_new()
              ...
              ssh_bind_listen($BIND, $PORT)
          - pattern: ssh_bind_accept($BIND, $SESSION)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: SSH server configuration catalogued - verify SSH server supports hybrid host keys and PQC algorithms
""",
        "test": """#include <libssh/libssh.h>

void ssh_server(int port) {
    ssh_bind bind = ssh_bind_new();
    ssh_bind_listen(bind, port);
    ssh_bind_accept(bind, nullptr);
}
""",
        "negative": """int ssh_port() {
    return 22;
}
""",
    },
    "cpp-pqc-grpc-tls": {
        "category": "pqc",
        "yaml": """rules:
  - id: cpp-pqc-grpc-tls
    message: gRPC TLS configuration detected - evaluate hybrid TLS and certificate support capability
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: grpc::SslCredentials($OPTIONS)
          - pattern: grpc::CreateChannel($TARGET, $CREDS)
          - pattern: grpc::CreateChannel($TARGET, grpc::InsecureChannelCredentials())
          - pattern: grpc::ServerBuilder()
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: gRPC TLS configuration documented - verify gRPC supports hybrid certificates and PQC cipher suites
""",
        "test": """#include <grpcpp/grpcpp.h>

void grpc_secure() {
    auto creds = grpc::SslCredentials(grpc::SslCredentialsOptions());
    auto channel = grpc::CreateChannel("localhost:50051", creds);
    auto insecure = grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials());
    grpc::ServerBuilder builder;
}
""",
        "negative": """const char *grpc_endpoint(const char *host, int port) {
    return "localhost:50051";
}
""",
    },
    "cpp-pqc-pki-infrastructure": {
        "category": "pqc",
        "yaml": """rules:
  - id: cpp-pqc-pki-infrastructure
    message: PKI and X.509 certificate operations detected - evaluate hybrid certificate infrastructure readiness
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: PEM_read_X509($BIO, $CERT, $CB, $U)
          - pattern: X509_new()
          - pattern: X509_sign($CERT, $KEY, $DIGEST)
          - pattern: X509_get_pubkey($CERT)
          - pattern: X509_verify($CERT, $KEY)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: PKI infrastructure usage documented - verify certificate authorities and systems support hybrid or PQC certificates
""",
        "test": """#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

void load_cert(BIO *bio) {
    X509 *cert = PEM_read_X509(bio, nullptr, nullptr, nullptr);
    X509_get_pubkey(cert);
}

void build_cert(X509 *cert, EVP_PKEY *key) {
    X509 *n = X509_new();
    X509_sign(n, key, EVP_sha256());
    X509_verify(cert, key);
}
""",
        "negative": """const char *pem_header() {
    return "-----BEGIN CERTIFICATE-----";
}
""",
    },
    "cpp-pqc-certificate-transparency": {
        "category": "pqc",
        "yaml": """rules:
  - id: cpp-pqc-certificate-transparency
    message: Certificate Transparency operations detected - ensure PQC certificate support
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: CTLOG_STORE_new()
          - pattern: SCT_new_from_base64($B64, $LOG)
          - pattern: CTLOG_STORE_load_default_file($STORE, $PATH)
    metadata:
      category: pqc_readiness
      cwe: CWE-295
      impact: Certificate Transparency logs must support PQC certificates
""",
        "test": """#include <openssl/ct.h>

void query_ct() {
    CTLOG_STORE *store = CTLOG_STORE_new();
    CTLOG_STORE_load_default_file(store, "/etc/ct/log_list.cnf");
    SCT *sct = SCT_new_from_base64("abc", nullptr);
}
""",
        "negative": """const char *ct_url(const char *base) {
    return "/ct/v1/get-sth";
}
""",
    },
    "cpp-pqc-elliptic-curves": {
        "category": "pqc",
        "yaml": """rules:
  - id: cpp-pqc-elliptic-curves
    message: Elliptic curve cryptography identified - catalog for PQC migration assessment
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: EC_KEY_new_by_curve_name($NID)
          - pattern: EC_KEY_generate_key($KEY)
          - pattern: ECDSA_sign($TYPE, $DIGEST, $LEN, $SIG, $SIGLEN, $KEY)
          - pattern: ECDSA_verify($TYPE, $DIGEST, $LEN, $SIG, $SIGLEN, $KEY)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Elliptic curve usage documented for PQC transition planning - verify system supports algorithm substitution
""",
        "test": """#include <openssl/ec.h>

void gen_ec_key() {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key);
}

void ecdsa_ops(EC_KEY *key) {
    ECDSA_sign(0, nullptr, 0, nullptr, nullptr, key);
    ECDSA_verify(0, nullptr, 0, nullptr, 0, key);
}
""",
        "negative": """const char *curve_name() {
    return "P-256";
}
""",
    },
    "cpp-pqc-message-signing": {
        "category": "pqc",
        "yaml": """rules:
  - id: cpp-pqc-message-signing
    message: Message signing operations detected - evaluate PQC signature algorithm support capability
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: EVP_DigestSignInit($CTX, $PKEY, $MD, $ENGINE, $KEY)
          - pattern: EVP_DigestSign($CTX, $SIG, $SIGLEN, $DATA, $LEN)
          - pattern: EVP_DigestVerifyInit($CTX, $PKEY, $MD, $ENGINE, $KEY)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Message signing mechanisms documented - verify signing libraries support hybrid or PQC signature algorithms
""",
        "test": """#include <openssl/evp.h>

void sign_message(EVP_MD_CTX *ctx, EVP_PKEY *key) {
    EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key);
    EVP_DigestSign(ctx, nullptr, nullptr, nullptr, 0);
}

void verify_message(EVP_MD_CTX *ctx, EVP_PKEY *key) {
    EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, key);
}
""",
        "negative": """const char *sign_string(const char *data) {
    return data;
}
""",
    },
    "cpp-pqc-config-profile-dependencies": {
        "category": "pqc",
        "yaml": """rules:
  - id: cpp-pqc-config-profile-dependencies
    message: TLS/crypto configuration detected - verify PQC algorithm compatibility across system components
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: getenv("OPENSSL_FIPS")
          - pattern: getenv("FIPS_MODE")
          - pattern: SSL_CTX_new($METHOD)
          - pattern: grpc::CreateChannel($TARGET, $CREDS)
          - pattern: $CTX.set_verify_mode($MODE)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Configuration may impose crypto requirements that create hard dependencies, causing system failures when PQC algorithms are enabled in mixed-version environments
""",
        "test": """#include <cstdlib>
#include <openssl/ssl.h>
#include <grpcpp/grpcpp.h>
#include <boost/asio/ssl.hpp>

void check_fips() {
    getenv("OPENSSL_FIPS");
    getenv("FIPS_MODE");
}

void tls_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    boost::asio::ssl::context boost_ctx(boost::asio::ssl::context::tlsv12);
    boost_ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials());
}
""",
        "negative": """const char *app_name() {
    return "myapp";
}
""",
    },
    "cpp-pqc-hardcoded-cipher-dependencies": {
        "category": "pqc",
        "yaml": """rules:
  - id: cpp-pqc-hardcoded-cipher-dependencies
    message: Hardcoded cipher suite or crypto algorithm configuration detected - may break when PQC algorithms are introduced
    severity: WARNING
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: SSL_CTX_set_cipher_list($CTX, $LIST)
          - pattern: SSL_CTX_set_min_proto_version($CTX, TLS1_2_VERSION)
          - pattern: SSL_CTX_set_max_proto_version($CTX, TLS1_2_VERSION)
          - pattern: $CTX.set_options($OPTIONS)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Hardcoded crypto configurations create dependencies that may break when PQC algorithms are enabled, especially in mixed-version environments
""",
        "test": """#include <openssl/ssl.h>
#include <boost/asio/ssl.hpp>

void restrict_ciphers(SSL_CTX *ctx) {
    SSL_CTX_set_cipher_list(ctx, "ECDHE+AESGCM:ECDHE+CHACHA20");
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    boost::asio::ssl::context boost_ctx(boost::asio::ssl::context::tlsv12);
    boost_ctx.set_options(boost::asio::ssl::context::no_sslv2);
}
""",
        "negative": """#include <openssl/ssl.h>

void default_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
}
""",
    },
    # --- Runtime security ---
    "cpp-tls-bypass": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: cpp-tls-bypass
    message: TLS security bypass detected - compromises transport security
    severity: ERROR
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: SSL_CTX_set_verify($CTX, SSL_VERIFY_NONE, $CB)
          - pattern: $CTX.set_verify_mode(boost::asio::ssl::verify_none)
          - pattern: "curl_easy_setopt($CURL, CURLOPT_SSL_VERIFYPEER, 0L)"
          - pattern: grpc::CreateChannel($TARGET, grpc::InsecureChannelCredentials())
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: TLS bypasses eliminate transport security and enable MITM attacks
""",
        "test": """#include <openssl/ssl.h>
#include <curl/curl.h>
#include <grpcpp/grpcpp.h>
#include <boost/asio/ssl.hpp>

void bypass_ssl(SSL_CTX *ctx, CURL *curl) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    boost::asio::ssl::context boost_ctx(boost::asio::ssl::context::tlsv12);
    boost_ctx.set_verify_mode(boost::asio::ssl::verify_none);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials());
}
""",
        "negative": """#include <openssl/ssl.h>

void secure_context(SSL_CTX *ctx) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
}
""",
    },
    "cpp-tls-version-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: cpp-tls-version-override
    message: TLS version override detected - may block TLS 1.3 or weaken transport security
    severity: WARNING
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: SSL_CTX_set_max_proto_version($CTX, TLS1_2_VERSION)
          - pattern: SSL_CTX_set_min_proto_version($CTX, TLS1_1_VERSION)
          - pattern: SSL_CTX_set_options($CTX, SSL_OP_NO_TLSv1_3)
          - pattern: $CTX.set_options(boost::asio::ssl::context::no_tlsv1_3)
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: TLS version restrictions may conflict with platform TLS profiles requiring TLS 1.3
""",
        "test": """#include <openssl/ssl.h>
#include <boost/asio/ssl.hpp>

void limit_tls(SSL_CTX *ctx) {
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
    boost::asio::ssl::context boost_ctx(boost::asio::ssl::context::tlsv12);
    boost_ctx.set_options(boost::asio::ssl::context::no_tlsv1_3);
}
""",
        "negative": """#include <openssl/ssl.h>

void modern_tls(SSL_CTX *ctx) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
}
""",
    },
    "cpp-certificate-validation-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: cpp-certificate-validation-override
    message: Certificate validation override detected - breaks trust chain
    severity: ERROR
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: SSL_CTX_set_verify($CTX, SSL_VERIFY_NONE, $CB)
          - pattern: $CTX.set_verify_mode(boost::asio::ssl::verify_none)
          - pattern: "curl_easy_setopt($CURL, CURLOPT_SSL_VERIFYPEER, 0L)"
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: Certificate validation override breaks trust chain and enables MITM attacks
""",
        "test": """#include <openssl/ssl.h>
#include <curl/curl.h>
#include <boost/asio/ssl.hpp>

void disable_validation(SSL_CTX *ctx, CURL *curl) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    boost::asio::ssl::context boost_ctx(boost::asio::ssl::context::tlsv12);
    boost_ctx.set_verify_mode(boost::asio::ssl::verify_none);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
}
""",
        "negative": """#include <openssl/ssl.h>

void enable_validation(SSL_CTX *ctx) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
}
""",
    },
    "cpp-http-client-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: cpp-http-client-tls-override
    message: HTTP client with custom TLS config detected - may override platform TLS profile settings
    severity: WARNING
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: curl_easy_init()
          - pattern: "curl_easy_setopt($CURL, CURLOPT_CAINFO, $PATH)"
          - pattern: "curl_easy_setopt($CURL, CURLOPT_SSLCERT, $PATH)"
          - pattern: boost::beast::ssl_stream<$STREAM>($STREAM, $CTX)
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: Custom TLS config in HTTP clients may override platform TLS profiles
""",
        "test": """#include <curl/curl.h>
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/ip/tcp.hpp>

void custom_clients() {
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/ca.pem");
    curl_easy_setopt(curl, CURLOPT_SSLCERT, "client.pem");
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tlsv12);
    boost::asio::ip::tcp::socket socket;
    boost::beast::ssl_stream<boost::asio::ip::tcp::socket> stream(socket, ctx);
}
""",
        "negative": """const char *fetch_url(const char *url) {
    return url;
}
""",
    },
    "cpp-http-server-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: cpp-http-server-tls-override
    message: HTTP server with custom TLS config detected - may override platform TLS profile settings
    severity: WARNING
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: SSL_CTX_use_certificate_file($CTX, $FILE, $TYPE)
          - pattern: SSL_CTX_use_PrivateKey_file($CTX, $FILE, $TYPE)
          - pattern: $CTX.set_verify_mode($MODE)
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: Custom TLS config in HTTP servers may override platform TLS profiles
""",
        "test": """#include <openssl/ssl.h>
#include <boost/asio/ssl.hpp>

void serve_tls(SSL_CTX *ctx) {
    SSL_CTX_use_certificate_file(ctx, "server.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM);
    boost::asio::ssl::context boost_ctx(boost::asio::ssl::context::tlsv12);
    boost_ctx.set_verify_mode(boost::asio::ssl::verify_peer);
}
""",
        "negative": """int listen_port(int port) {
    return port;
}
""",
    },
    "cpp-grpc-tls-credential-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: cpp-grpc-tls-credential-override
    message: gRPC TLS credential override detected - may bypass service mesh security
    severity: ERROR
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: grpc::CreateChannel($TARGET, grpc::InsecureChannelCredentials())
          - pattern: grpc::experimental::LocalCredentials($OPTIONS)
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: gRPC credential override bypasses service mesh security and mTLS policies
""",
        "test": """#include <grpcpp/grpcpp.h>

void insecure_grpc() {
    auto channel = grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials());
    auto creds = grpc::experimental::LocalCredentials(grpc_local_connect_type::LOCAL_TCP);
}
""",
        "negative": """const char *grpc_target(const char *host) {
    return host;
}
""",
    },
    "cpp-kubernetes-client-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: cpp-kubernetes-client-tls-override
    message: Kubernetes client TLS configuration override detected
    severity: WARNING
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: getenv("KUBERNETES_SERVICE_HOST")
          - pattern: getenv("KUBECONFIG")
          - pattern: "curl_easy_setopt($CURL, CURLOPT_SSL_VERIFYPEER, 0L)"
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: Kubernetes client TLS override can bypass cluster security policies
""",
        "test": """#include <cstdlib>
#include <curl/curl.h>

void k8s_insecure(CURL *curl) {
    getenv("KUBERNETES_SERVICE_HOST");
    getenv("KUBECONFIG");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
}
""",
        "negative": """const char *cluster_name() {
    return "production";
}
""",
    },
    "cpp-service-mesh-bypass": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: cpp-service-mesh-bypass
    message: Service mesh TLS bypass detected - communication outside mesh security
    severity: ERROR
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: |
              sprintf($URL, "http://%s:%d", $HOST, $PORT)
              ...
              curl_easy_perform($CURL)
          - pattern: |
              snprintf($URL, $SIZE, "http://%s", $ENDPOINT)
              ...
              curl_easy_perform($CURL)
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: Service mesh bypass eliminates mTLS protection and security observability
""",
        "test": """#include <cstdio>
#include <curl/curl.h>

void mesh_bypass(CURL *curl, const char *host, int port) {
    char url[256];
    sprintf(url, "http://%s:%d", host, port);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_perform(curl);
}

void endpoint_bypass(CURL *curl, const char *endpoint) {
    char url[256];
    snprintf(url, sizeof(url), "http://%s", endpoint);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_perform(curl);
}
""",
        "negative": """const char *mesh_url(const char *host) {
    return "https://service";
}
""",
    },
    "cpp-reflection-basic-usage": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: cpp-reflection-basic-usage
    message: Basic reflection usage detected - mapping reflection landscape
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: dlopen($LIB, $FLAGS)
          - pattern: dlsym($HANDLE, $SYM)
          - pattern: dlclose($HANDLE)
    metadata:
      category: reflection
      cwe: CWE-200
      impact: Basic reflection usage for landscape mapping
""",
        "test": """#include <dlfcn.h>

void inspect_symbols(const char *lib, const char *sym) {
    void *handle = dlopen(lib, RTLD_LAZY);
    void *fn = dlsym(handle, sym);
    dlclose(handle);
}
""",
        "negative": """int object_id(void *obj) {
    return 0;
}
""",
    },
    "cpp-reflection-advanced-patterns": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: cpp-reflection-advanced-patterns
    message: Advanced reflection patterns detected - landscape mapping
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: $FN = ($TYPE)dlsym($HANDLE, $SYM)
          - pattern: reinterpret_cast<$TYPE>($EXPR)
    metadata:
      category: reflection
      cwe: CWE-20
      impact: Can bypass type safety and create security vulnerabilities
""",
        "test": """#include <dlfcn.h>

void dynamic_cast_ptr(void *handle, const char *sym) {
    void (*fn)(void) = (void (*)(void))dlsym(handle, sym);
    void *p = reinterpret_cast<void *>(fn);
}
""",
        "negative": """const char *static_symbol() {
    return "main";
}
""",
    },
    "cpp-reflection-structural-manipulation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: cpp-reflection-structural-manipulation
    message: Reflection structural manipulation detected - landscape mapping
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: memcpy($DST, $SRC, $SIZE)
          - pattern: memmove($DST, $SRC, $SIZE)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Runtime type manipulation can bypass compile-time safety
""",
        "test": """#include <cstring>

struct Foo { int x; int y; };

void copy_struct(Foo *dst, Foo *src) {
    memcpy(dst, src, sizeof(Foo));
    memmove(dst, src, sizeof(Foo));
}
""",
        "negative": """int read_field(Foo *f) {
    return f->x;
}
""",
    },
    "cpp-reflection-type-assertion": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: cpp-reflection-type-assertion
    message: Reflection-based type assertion detected - potential type confusion risk
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: dynamic_cast<$TYPE>($EXPR)
          - pattern: static_cast<$TYPE>($EXPR)
          - pattern: reinterpret_cast<$TYPE>($EXPR)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Type assertions from reflection can lead to type confusion vulnerabilities
""",
        "test": """struct Base {};
struct Derived : Base {};

void check_types(Base *b, void *p) {
    Derived *d = dynamic_cast<Derived *>(b);
    int *ip = static_cast<int *>(p);
    void *vp = reinterpret_cast<void *>(ip);
}
""",
        "negative": """const char *type_name(Base *obj) {
    return "Base";
}
""",
    },
    "cpp-reflection-value-mutation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: cpp-reflection-value-mutation
    message: Reflection-based value mutation detected - landscape mapping
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: "*$PTR = $VALUE"
          - pattern: memcpy($DST, &$VALUE, $SIZE)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Reflection-based value mutation bypasses type safety and obscures data flow
""",
        "test": """#include <cstring>

void mutate_values(int *ptr, int value) {
    *ptr = value;
    int local = value;
    memcpy(ptr, &local, sizeof(int));
}
""",
        "negative": """int copy_value(int value) {
    return value;
}
""",
    },
    "cpp-dynamic-method-invocation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: cpp-dynamic-method-invocation
    message: Dynamic method invocation patterns detected - landscape mapping
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: $FN = ($TYPE)dlsym($HANDLE, $SYM)
          - pattern: |
              $FN = ($TYPE)dlsym($HANDLE, $SYM)
              ...
              $FN($ARGS)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Dynamic method calls can bypass authentication, authorization, and input validation
""",
        "test": """#include <dlfcn.h>

void call_dynamic(void *handle, const char *name) {
    int (*fn)(int) = (int (*)(int))dlsym(handle, name);
    fn(42);
}

void call_with_args(void *handle, const char *name, int arg) {
    int (*method)(int) = (int (*)(int))dlsym(handle, name);
    method(arg);
}
""",
        "negative": """int call_direct(int (*fn)(int)) {
    return fn(1);
}
""",
    },
    "cpp-unsafe-pointer-operations": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: cpp-unsafe-pointer-operations
    message: Unsafe memory operations detected - landscape mapping
    severity: INFO
    languages:
      - cpp
    patterns:
      - pattern-either:
          - pattern: memcpy($DST, $SRC, $COUNT)
          - pattern: memmove($DST, $SRC, $COUNT)
          - pattern: realloc($PTR, $SIZE)
    metadata:
      category: memory_safety
      cwe: CWE-119
      impact: Unsafe memory operations can lead to memory corruption
""",
        "test": """#include <cstdlib>
#include <cstring>

void unsafe_ops(void *dst, void *src, size_t count, void *ptr) {
    memcpy(dst, src, count);
    memmove(dst, src, count);
    realloc(ptr, count);
}
""",
        "negative": """size_t safe_len(const char *data) {
    return 0;
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
            lines.append(f'    message: "{f["message"]}"')
        lines.append("")
        lines.append("no_findings:")
        lines.append(f"  - negative_cases.{EXT}")
        (test_dir / "expected.yml").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    write_files()
    write_expected()
    print(f"Generated {len(RULES)} C++ rules with tests")
