#include <openssl/ssl.h>
#include <boost/asio/ssl.hpp>

void serve_tls(SSL_CTX *ctx) {
    SSL_CTX_use_certificate_file(ctx, "server.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM);
    boost::asio::ssl::context boost_ctx(boost::asio::ssl::context::tlsv12);
    boost_ctx.set_verify_mode(boost::asio::ssl::verify_peer);
}
