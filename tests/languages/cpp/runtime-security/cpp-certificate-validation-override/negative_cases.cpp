#include <openssl/ssl.h>

void enable_validation(SSL_CTX *ctx) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
}
