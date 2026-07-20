#include <cstdlib>
#include <openssl/ssl.h>
#include <grpcpp/grpcpp.h>
#include <boost/asio/ssl.hpp>

void check_fips() {
    getenv("OPENSSL_FIPS");
    getenv("FIPS_MODE");
}

void tls_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    boost::asio::ssl::context boost_ctx(boost::asio::ssl::context::tlsv12);
    boost_ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials());
}
