#include <openssl/ssl.h>
#include <curl/curl.h>
#include <grpcpp/grpcpp.h>
#include <boost/asio/ssl.hpp>

void bypass_ssl(SSL_CTX *ctx, CURL *curl) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    boost::asio::ssl::context boost_ctx(boost::asio::ssl::context::tlsv12);
    boost_ctx.set_verify_mode(boost::asio::ssl::verify_none);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials());
}
