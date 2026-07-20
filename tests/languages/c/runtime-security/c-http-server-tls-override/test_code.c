#include <openssl/ssl.h>
#include <openssl/bio.h>

void serve_tls(SSL_CTX *ctx) {
    SSL_CTX_use_certificate_file(ctx, "server.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM);
    BIO_new_ssl(ctx, 0);
}
