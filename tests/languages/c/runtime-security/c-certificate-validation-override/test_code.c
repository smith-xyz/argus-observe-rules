#include <openssl/ssl.h>
#include <curl/curl.h>

void disable_validation(SSL_CTX *ctx, CURL *curl) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_cert_verify_callback(ctx, NULL, NULL);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
}
