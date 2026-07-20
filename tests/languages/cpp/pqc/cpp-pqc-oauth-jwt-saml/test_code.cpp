#include <curl/curl.h>
#include <lasso/login.h>

void oauth_bearer(CURL *curl, const char *token) {
    curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, token);
}

void saml_flow() {
    LassoLogin *login = lasso_login_new(nullptr);
    lasso_login_init_auth(login);
    lasso_login_process_auth(login, nullptr);
}
