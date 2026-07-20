#include <openssl/ssl.h>

void limit_tls(SSL_CTX *ctx) {
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
}
