#include <openssl/ssl.h>
#include <boost/asio/ssl.hpp>

void restrict_ciphers(SSL_CTX *ctx) {
    SSL_CTX_set_cipher_list(ctx, "ECDHE+AESGCM:ECDHE+CHACHA20");
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    boost::asio::ssl::context boost_ctx(boost::asio::ssl::context::tlsv12);
    boost_ctx.set_options(boost::asio::ssl::context::no_sslv2);
}
