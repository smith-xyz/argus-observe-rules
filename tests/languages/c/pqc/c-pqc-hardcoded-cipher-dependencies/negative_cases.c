#include <openssl/ssl.h>

void default_context(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
}
