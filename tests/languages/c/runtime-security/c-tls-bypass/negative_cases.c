#include <openssl/ssl.h>

void secure_context(SSL_CTX *ctx) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}
