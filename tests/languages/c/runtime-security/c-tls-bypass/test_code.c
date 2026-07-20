#include <openssl/ssl.h>
#include <curl/curl.h>

void bypass_ssl(SSL_CTX *ctx, SSL *ssl, CURL *curl) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
}
