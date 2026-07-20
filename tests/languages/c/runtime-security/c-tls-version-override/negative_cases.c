#include <openssl/ssl.h>

void modern_tls(SSL_CTX *ctx) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
}
