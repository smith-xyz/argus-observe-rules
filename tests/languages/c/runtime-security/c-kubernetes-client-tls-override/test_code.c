#include <stdlib.h>
#include <curl/curl.h>

void k8s_insecure(CURL *curl) {
    getenv("KUBERNETES_SERVICE_HOST");
    getenv("KUBECONFIG");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
}
