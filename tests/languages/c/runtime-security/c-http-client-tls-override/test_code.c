#include <curl/curl.h>

void custom_curl_tls(void) {
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/ca.pem");
    curl_easy_setopt(curl, CURLOPT_SSLCERT, "client.pem");
    curl_easy_setopt(curl, CURLOPT_SSLKEY, "client.key");
}
