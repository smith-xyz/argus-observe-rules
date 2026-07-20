#include <stdlib.h>
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
