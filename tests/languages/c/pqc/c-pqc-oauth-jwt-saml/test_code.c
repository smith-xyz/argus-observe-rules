#include <curl/curl.h>
#include <lasso/login.h>
#include <lasso/provider.h>

void oauth_bearer(CURL *curl, char *token) {
    curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, token);
}

void saml_login() {
    LassoLogin *login = lasso_login_new(NULL);
    lasso_login_init_auth(login);
    lasso_login_process_auth(login, NULL);
}

void saml_provider() {
    lasso_provider_new(NULL);
}
