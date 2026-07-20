#include <cstdio>
#include <curl/curl.h>

void mesh_bypass(CURL *curl, const char *host, int port) {
    char url[256];
    sprintf(url, "http://%s:%d", host, port);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_perform(curl);
}

void endpoint_bypass(CURL *curl, const char *endpoint) {
    char url[256];
    snprintf(url, sizeof(url), "http://%s", endpoint);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_perform(curl);
}
