#!/usr/bin/env python3
"""Generate C PQC and runtime-security rules with tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_PQC = ROOT / "rules/languages/c/pqc"
RULES_RT = ROOT / "rules/languages/c/runtime-security"
TESTS = ROOT / "tests/languages/c"
EXT = "c"

RULES: dict[str, dict] = {
    # --- PQC ---
    "c-pqc-jwt-operations": {
        "category": "pqc",
        "yaml": """rules:
  - id: c-pqc-jwt-operations
    message: JWT token operations detected - verify PQC signature algorithm support
    severity: INFO
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: jwt_encode($JWT, $KEY, $ALG)
          - pattern: jwt_decode($JWT, $TOKEN, $LEN, $KEY, $ALG)
          - pattern: jwt_new()
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: JWT infrastructure may need updates for PQC signature algorithms
""",
        "test": """#include <jwt.h>

void jwt_encode_op(jwt_t *jwt, char *key) {
    jwt_encode(jwt, key, "HS256");
}

void jwt_decode_op(jwt_t **jwt, char *key) {
    jwt_decode(jwt, "token", 6, key, "HS256");
}

void jwt_create() {
    jwt_t *jwt = jwt_new();
}
""",
        "negative": """char *build_token(const char *header, const char *payload) {
    return "header.payload.sig";
}
""",
    },
    "c-pqc-jwt-rsa-ecdsa": {
        "category": "pqc",
        "yaml": """rules:
  - id: c-pqc-jwt-rsa-ecdsa
    message: JWT with RSA/ECDSA signatures detected - assess PQC signature algorithm support readiness
    severity: INFO
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: jwt_set_alg($JWT, JWT_ALG_RS256, $KEY, $LEN)
          - pattern: jwt_set_alg($JWT, JWT_ALG_RS384, $KEY, $LEN)
          - pattern: jwt_set_alg($JWT, JWT_ALG_RS512, $KEY, $LEN)
          - pattern: jwt_set_alg($JWT, JWT_ALG_ES256, $KEY, $LEN)
          - pattern: jwt_set_alg($JWT, JWT_ALG_ES384, $KEY, $LEN)
          - pattern: jwt_set_alg($JWT, JWT_ALG_ES512, $KEY, $LEN)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: JWT signature algorithms catalogued - verify JWT library supports hybrid or PQC signature methods
""",
        "test": """#include <jwt.h>

void sign_rs256(jwt_t *jwt) {
    jwt_set_alg(jwt, JWT_ALG_RS256, NULL, 0);
}

void sign_es256(jwt_t *jwt) {
    jwt_set_alg(jwt, JWT_ALG_ES256, NULL, 0);
}

void sign_rs512(jwt_t *jwt) {
    jwt_set_alg(jwt, JWT_ALG_RS512, NULL, 0);
}
""",
        "negative": """#include <jwt.h>

void sign_hs256(jwt_t *jwt) {
    jwt_set_alg(jwt, JWT_ALG_HS256, NULL, 0);
}
""",
    },
    "c-pqc-oauth-jwt-saml": {
        "category": "pqc",
        "yaml": """rules:
  - id: c-pqc-oauth-jwt-saml
    message: OAuth/SAML/OIDC operations detected - assess identity protocol PQC signature readiness
    severity: INFO
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: "curl_easy_setopt($CURL, CURLOPT_XOAUTH2_BEARER, $TOKEN)"
          - pattern: lasso_login_new($PROVIDER)
          - pattern: lasso_login_init_auth($LOGIN)
          - pattern: lasso_login_process_auth($LOGIN, $REQUEST)
          - pattern: lasso_provider_new($METADATA)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Identity protocol usage documented - verify OAuth/SAML/OIDC libraries support hybrid or PQC signature algorithms
""",
        "test": """#include <curl/curl.h>
#include <lasso/login.h>
#include <lasso/provider.h>

void oauth_bearer(CURL *curl, char *token) {
    curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, token);
}

void saml_login() {
    LassoLogin *login = lasso_login_new(NULL);
    lasso_login_init_auth(login);
    lasso_login_process_auth(login, NULL);
}

void saml_provider() {
    lasso_provider_new(NULL);
}
""",
        "negative": """const char *parse_bearer(const char *header) {
    return header;
}
""",
    },
    "c-pqc-ssh-client": {
        "category": "pqc",
        "yaml": """rules:
  - id: c-pqc-ssh-client
    message: SSH client configuration detected - evaluate PQC SSH algorithm support readiness
    severity: INFO
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: ssh_new()
          - pattern: |
              $SESSION = ssh_new()
              ...
              ssh_connect($SESSION)
          - pattern: ssh_options_set($SESSION, SSH_OPTIONS_HOST, $HOST)
          - pattern: ssh_userauth_publickey_auto($SESSION, $USER, $KEY)
          - pattern: ssh_userauth_password($SESSION, $USER, $PASS)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: SSH client configuration documented - verify SSH library supports hybrid or PQC key exchange and authentication algorithms
""",
        "test": """#include <libssh/libssh.h>

void ssh_connect_client(const char *host) {
    ssh_session session = ssh_new();
    ssh_options_set(session, SSH_OPTIONS_HOST, host);
    ssh_connect(session);
    ssh_userauth_publickey_auto(session, NULL, NULL);
}

void ssh_password_auth(ssh_session session, const char *user, const char *pass) {
    ssh_userauth_password(session, user, pass);
}
""",
        "negative": """const char *ssh_command(const char *host, const char *user) {
    return "ssh";
}
""",
    },
    "c-pqc-ssh-server": {
        "category": "pqc",
        "yaml": """rules:
  - id: c-pqc-ssh-server
    message: SSH server configuration detected - assess PQC SSH algorithm implementation capability
    severity: INFO
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: ssh_bind_new()
          - pattern: |
              $BIND = ssh_bind_new()
              ...
              ssh_bind_listen($BIND, $PORT)
          - pattern: ssh_bind_accept($BIND, $SESSION)
          - pattern: ssh_bind_options_set($BIND, SSH_BIND_OPTIONS_BINDPORT, $PORT)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: SSH server configuration catalogued - verify SSH server supports hybrid host keys and PQC algorithms
""",
        "test": """#include <libssh/libssh.h>

void start_ssh_server(int port) {
    ssh_bind bind = ssh_bind_new();
    ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_listen(bind, port);
    ssh_bind_accept(bind, NULL);
}
""",
        "negative": """int ssh_port(void) {
    return 22;
}
""",
    },
    "c-pqc-grpc-tls": {
        "category": "pqc",
        "yaml": """rules:
  - id: c-pqc-grpc-tls
    message: gRPC TLS configuration detected - evaluate hybrid TLS and certificate support capability
    severity: INFO
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: grpc_ssl_credentials_create($ROOT, $KEY, $CERT, $FLAGS)
          - pattern: grpc_insecure_channel_create($TARGET, $ARGS, $CREDS)
          - pattern: grpc_server_credentials_create($CREDS)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: gRPC TLS configuration documented - verify gRPC supports hybrid certificates and PQC cipher suites
""",
        "test": """#include <grpc/grpc.h>
#include <grpc/grpc_security.h>

void grpc_secure_channel(void) {
    grpc_channel_credentials *creds = grpc_ssl_credentials_create(NULL, NULL, NULL, NULL);
    grpc_channel *ch = grpc_insecure_channel_create("localhost:50051", NULL, NULL);
    grpc_server_credentials *server = grpc_server_credentials_create(creds);
}
""",
        "negative": """const char *grpc_target(const char *host, int port) {
    return "localhost:50051";
}
""",
    },
    "c-pqc-pki-infrastructure": {
        "category": "pqc",
        "yaml": """rules:
  - id: c-pqc-pki-infrastructure
    message: PKI and X.509 certificate operations detected - evaluate hybrid certificate infrastructure readiness
    severity: INFO
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: PEM_read_X509($BIO, $CERT, $CB, $U)
          - pattern: d2i_X509_bio($BIO, $CERT)
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
    X509 *cert = PEM_read_X509(bio, NULL, NULL, NULL);
    X509_get_pubkey(cert);
}

void build_cert(X509 *cert, EVP_PKEY *key) {
    X509 *n = X509_new();
    X509_sign(n, key, EVP_sha256());
    X509_verify(cert, key);
}

void der_cert(BIO *bio, X509 **cert) {
    d2i_X509_bio(bio, cert);
}
""",
        "negative": """const char *pem_header(void) {
    return "-----BEGIN CERTIFICATE-----";
}
""",
    },
    "c-pqc-certificate-transparency": {
        "category": "pqc",
        "yaml": """rules:
  - id: c-pqc-certificate-transparency
    message: Certificate Transparency operations detected - ensure PQC certificate support
    severity: INFO
    languages:
      - c
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

void query_ct_log(void) {
    CTLOG_STORE *store = CTLOG_STORE_new();
    CTLOG_STORE_load_default_file(store, "/etc/ct/log_list.cnf");
    SCT *sct = SCT_new_from_base64("abc", NULL);
}
""",
        "negative": """const char *ct_url(const char *base) {
    return "/ct/v1/get-sth";
}
""",
    },
    "c-pqc-elliptic-curves": {
        "category": "pqc",
        "yaml": """rules:
  - id: c-pqc-elliptic-curves
    message: Elliptic curve cryptography identified - catalog for PQC migration assessment
    severity: INFO
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: EC_KEY_new_by_curve_name($NID)
          - pattern: EC_KEY_generate_key($KEY)
          - pattern: ECDSA_sign($TYPE, $DIGEST, $LEN, $SIG, $SIGLEN, $KEY)
          - pattern: ECDSA_verify($TYPE, $DIGEST, $LEN, $SIG, $SIGLEN, $KEY)
          - pattern: EC_KEY_get0_group($KEY)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Elliptic curve usage documented for PQC transition planning - verify system supports algorithm substitution
""",
        "test": """#include <openssl/ec.h>

void gen_ec_key(void) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key);
    EC_KEY_get0_group(key);
}

void ecdsa_ops(EC_KEY *key) {
    ECDSA_sign(0, NULL, 0, NULL, NULL, key);
    ECDSA_verify(0, NULL, 0, NULL, 0, key);
}
""",
        "negative": """const char *curve_name(void) {
    return "P-256";
}
""",
    },
    "c-pqc-message-signing": {
        "category": "pqc",
        "yaml": """rules:
  - id: c-pqc-message-signing
    message: Message signing operations detected - evaluate PQC signature algorithm support capability
    severity: INFO
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: EVP_DigestSignInit($CTX, $PKEY, $MD, $ENGINE, $KEY)
          - pattern: EVP_DigestSign($CTX, $SIG, $SIGLEN, $DATA, $LEN)
          - pattern: EVP_SignFinal($CTX, $SIG, $SIGLEN, $KEY)
          - pattern: EVP_DigestVerifyInit($CTX, $PKEY, $MD, $ENGINE, $KEY)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Message signing mechanisms documented - verify signing libraries support hybrid or PQC signature algorithms
""",
        "test": """#include <openssl/evp.h>

void sign_message(EVP_MD_CTX *ctx, EVP_PKEY *key) {
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key);
    EVP_DigestSign(ctx, NULL, NULL, NULL, 0);
}

void sign_final(EVP_MD_CTX *ctx, EVP_PKEY *key) {
    EVP_SignFinal(ctx, NULL, NULL, key);
}

void verify_init(EVP_MD_CTX *ctx, EVP_PKEY *key) {
    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key);
}
""",
        "negative": """const char *sign_string(const char *data) {
    return data;
}
""",
    },
    "c-pqc-config-profile-dependencies": {
        "category": "pqc",
        "yaml": """rules:
  - id: c-pqc-config-profile-dependencies
    message: TLS/crypto configuration detected - verify PQC algorithm compatibility across system components
    severity: INFO
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: getenv("OPENSSL_FIPS")
          - pattern: getenv("FIPS_MODE")
          - pattern: getenv("OPENSSL_CONF")
          - pattern: SSL_CTX_new($METHOD)
          - pattern: grpc_ssl_credentials_create($ROOT, $KEY, $CERT, $FLAGS)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Configuration may impose crypto requirements that create hard dependencies, causing system failures when PQC algorithms are enabled in mixed-version environments
""",
        "test": """#include <stdlib.h>
#include <openssl/ssl.h>
#include <grpc/grpc_security.h>

void check_fips(void) {
    getenv("OPENSSL_FIPS");
    getenv("FIPS_MODE");
    getenv("OPENSSL_CONF");
}

void tls_context(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    grpc_ssl_credentials_create(NULL, NULL, NULL, NULL);
}
""",
        "negative": """const char *app_name(void) {
    return "myapp";
}
""",
    },
    "c-pqc-hardcoded-cipher-dependencies": {
        "category": "pqc",
        "yaml": """rules:
  - id: c-pqc-hardcoded-cipher-dependencies
    message: Hardcoded cipher suite or crypto algorithm configuration detected - may break when PQC algorithms are introduced
    severity: WARNING
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: SSL_CTX_set_cipher_list($CTX, $LIST)
          - pattern: SSL_CTX_set_min_proto_version($CTX, TLS1_2_VERSION)
          - pattern: SSL_CTX_set_max_proto_version($CTX, TLS1_2_VERSION)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Hardcoded crypto configurations create dependencies that may break when PQC algorithms are enabled, especially in mixed-version environments
""",
        "test": """#include <openssl/ssl.h>

void restrict_ciphers(SSL_CTX *ctx) {
    SSL_CTX_set_cipher_list(ctx, "ECDHE+AESGCM:ECDHE+CHACHA20");
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
}
""",
        "negative": """#include <openssl/ssl.h>

void default_context(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
}
""",
    },
    # --- Runtime security ---
    "c-tls-bypass": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: c-tls-bypass
    message: TLS security bypass detected - compromises transport security
    severity: ERROR
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: SSL_CTX_set_verify($CTX, SSL_VERIFY_NONE, $CB)
          - pattern: SSL_set_verify($SSL, SSL_VERIFY_NONE, $CB)
          - pattern: "curl_easy_setopt($CURL, CURLOPT_SSL_VERIFYPEER, 0L)"
          - pattern: "curl_easy_setopt($CURL, CURLOPT_SSL_VERIFYHOST, 0L)"
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: TLS bypasses eliminate transport security and enable MITM attacks
""",
        "test": """#include <openssl/ssl.h>
#include <curl/curl.h>

void bypass_ssl(SSL_CTX *ctx, SSL *ssl, CURL *curl) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
}
""",
        "negative": """#include <openssl/ssl.h>

void secure_context(SSL_CTX *ctx) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}
""",
    },
    "c-tls-version-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: c-tls-version-override
    message: TLS version override detected - may block TLS 1.3 or weaken transport security
    severity: WARNING
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: SSL_CTX_set_max_proto_version($CTX, TLS1_2_VERSION)
          - pattern: SSL_CTX_set_min_proto_version($CTX, TLS1_1_VERSION)
          - pattern: SSL_CTX_set_min_proto_version($CTX, TLS1_VERSION)
          - pattern: SSL_CTX_set_options($CTX, SSL_OP_NO_TLSv1_3)
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: TLS version restrictions may conflict with platform TLS profiles requiring TLS 1.3
""",
        "test": """#include <openssl/ssl.h>

void limit_tls(SSL_CTX *ctx) {
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
}
""",
        "negative": """#include <openssl/ssl.h>

void modern_tls(SSL_CTX *ctx) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
}
""",
    },
    "c-certificate-validation-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: c-certificate-validation-override
    message: Certificate validation override detected - breaks trust chain
    severity: ERROR
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: SSL_CTX_set_verify($CTX, SSL_VERIFY_NONE, $CB)
          - pattern: SSL_CTX_set_cert_verify_callback($CTX, $CB, $ARG)
          - pattern: "curl_easy_setopt($CURL, CURLOPT_SSL_VERIFYPEER, 0L)"
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: Certificate validation override breaks trust chain and enables MITM attacks
""",
        "test": """#include <openssl/ssl.h>
#include <curl/curl.h>

void disable_validation(SSL_CTX *ctx, CURL *curl) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_cert_verify_callback(ctx, NULL, NULL);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
}
""",
        "negative": """#include <openssl/ssl.h>

void enable_validation(SSL_CTX *ctx) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}
""",
    },
    "c-http-client-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: c-http-client-tls-override
    message: HTTP client with custom TLS config detected - may override platform TLS profile settings
    severity: WARNING
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: curl_easy_init()
          - pattern: "curl_easy_setopt($CURL, CURLOPT_CAINFO, $PATH)"
          - pattern: "curl_easy_setopt($CURL, CURLOPT_SSLCERT, $PATH)"
          - pattern: "curl_easy_setopt($CURL, CURLOPT_SSLKEY, $PATH)"
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: Custom TLS config in HTTP clients may override platform TLS profiles
""",
        "test": """#include <curl/curl.h>

void custom_curl_tls(void) {
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/ca.pem");
    curl_easy_setopt(curl, CURLOPT_SSLCERT, "client.pem");
    curl_easy_setopt(curl, CURLOPT_SSLKEY, "client.key");
}
""",
        "negative": """const char *fetch_url(const char *url) {
    return url;
}
""",
    },
    "c-http-server-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: c-http-server-tls-override
    message: HTTP server with custom TLS config detected - may override platform TLS profile settings
    severity: WARNING
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: SSL_CTX_use_certificate_file($CTX, $FILE, $TYPE)
          - pattern: SSL_CTX_use_PrivateKey_file($CTX, $FILE, $TYPE)
          - pattern: BIO_new_ssl($CTX, $ACCEPT)
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: Custom TLS config in HTTP servers may override platform TLS profiles
""",
        "test": """#include <openssl/ssl.h>
#include <openssl/bio.h>

void serve_tls(SSL_CTX *ctx) {
    SSL_CTX_use_certificate_file(ctx, "server.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM);
    BIO_new_ssl(ctx, 0);
}
""",
        "negative": """int listen_port(int port) {
    return port;
}
""",
    },
    "c-grpc-tls-credential-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: c-grpc-tls-credential-override
    message: gRPC TLS credential override detected - may bypass service mesh security
    severity: ERROR
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: grpc_insecure_channel_create($TARGET, $ARGS, $CREDS)
          - pattern: grpc_local_credentials_create()
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: gRPC credential override bypasses service mesh security and mTLS policies
""",
        "test": """#include <grpc/grpc.h>
#include <grpc/grpc_security.h>

void insecure_grpc(void) {
    grpc_channel *ch = grpc_insecure_channel_create("localhost:50051", NULL, NULL);
    grpc_channel_credentials *creds = grpc_local_credentials_create();
}
""",
        "negative": """const char *grpc_target(const char *host) {
    return host;
}
""",
    },
    "c-kubernetes-client-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: c-kubernetes-client-tls-override
    message: Kubernetes client TLS configuration override detected
    severity: WARNING
    languages:
      - c
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
        "test": """#include <stdlib.h>
#include <curl/curl.h>

void k8s_insecure(CURL *curl) {
    getenv("KUBERNETES_SERVICE_HOST");
    getenv("KUBECONFIG");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
}
""",
        "negative": """const char *cluster_name(void) {
    return "production";
}
""",
    },
    "c-service-mesh-bypass": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: c-service-mesh-bypass
    message: Service mesh TLS bypass detected - communication outside mesh security
    severity: ERROR
    languages:
      - c
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
        "test": """#include <stdio.h>
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
    "c-reflection-basic-usage": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: c-reflection-basic-usage
    message: Basic reflection usage detected - mapping reflection landscape
    severity: INFO
    languages:
      - c
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
    "c-reflection-advanced-patterns": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: c-reflection-advanced-patterns
    message: Advanced reflection patterns detected - landscape mapping
    severity: INFO
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: $FN = ($TYPE)dlsym($HANDLE, $SYM)
          - pattern: |
              $PTR = dlsym($HANDLE, $SYM)
              ...
              (($TYPE)$PTR)()
    metadata:
      category: reflection
      cwe: CWE-20
      impact: Can bypass type safety and create security vulnerabilities
""",
        "test": """#include <dlfcn.h>

void dynamic_call(void *handle, const char *sym) {
    void (*fn)(void) = (void (*)(void))dlsym(handle, sym);
    fn();
}

void indirect_call(void *handle, const char *sym) {
    void *ptr = dlsym(handle, sym);
    ((void (*)(void))ptr)();
}
""",
        "negative": """const char *static_symbol(void) {
    return "main";
}
""",
    },
    "c-reflection-structural-manipulation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: c-reflection-structural-manipulation
    message: Reflection structural manipulation detected - landscape mapping
    severity: INFO
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: memcpy($DST, $SRC, $SIZE)
          - pattern: memmove($DST, $SRC, $SIZE)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Runtime type manipulation can bypass compile-time safety
""",
        "test": """#include <string.h>

struct Foo { int x; int y; };

void copy_struct(struct Foo *dst, struct Foo *src) {
    memcpy(dst, src, sizeof(struct Foo));
    memmove(dst, src, sizeof(struct Foo));
}
""",
        "negative": """int read_field(struct Foo *f) {
    return f->x;
}
""",
    },
    "c-reflection-type-assertion": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: c-reflection-type-assertion
    message: Reflection-based type assertion detected - potential type confusion risk
    severity: INFO
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: ($TYPE *)$EXPR
          - pattern: (const $TYPE *)$EXPR
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Type assertions from reflection can lead to type confusion vulnerabilities
""",
        "test": """void check_types(void *obj, const void *base) {
    int *ip = (int *)obj;
    const char *cp = (const char *)base;
}
""",
        "negative": """int type_tag(void *obj) {
    return 0;
}
""",
    },
    "c-reflection-value-mutation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: c-reflection-value-mutation
    message: Reflection-based value mutation detected - landscape mapping
    severity: INFO
    languages:
      - c
    patterns:
      - pattern-either:
          - pattern: "*$PTR = $VALUE"
          - pattern: memcpy($DST, &$VALUE, $SIZE)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Reflection-based value mutation bypasses type safety and obscures data flow
""",
        "test": """#include <string.h>

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
    "c-dynamic-method-invocation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: c-dynamic-method-invocation
    message: Dynamic method invocation patterns detected - landscape mapping
    severity: INFO
    languages:
      - c
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
    "c-unsafe-pointer-operations": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: c-unsafe-pointer-operations
    message: Unsafe memory operations detected - landscape mapping
    severity: INFO
    languages:
      - c
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
        "test": """#include <stdlib.h>
#include <string.h>

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
    print(f"Generated {len(RULES)} C rules with tests")
