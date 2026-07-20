#include <openssl/ssl.h>
#include <curl/curl.h>
#include <boost/asio/ssl.hpp>

void disable_validation(SSL_CTX *ctx, CURL *curl) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    boost::asio::ssl::context boost_ctx(boost::asio::ssl::context::tlsv12);
    boost_ctx.set_verify_mode(boost::asio::ssl::verify_none);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
}
