#include <curl/curl.h>
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/ip/tcp.hpp>

void custom_clients() {
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/ca.pem");
    curl_easy_setopt(curl, CURLOPT_SSLCERT, "client.pem");
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tlsv12);
    boost::asio::ip::tcp::socket socket;
    boost::beast::ssl_stream<boost::asio::ip::tcp::socket> stream(socket, ctx);
}
