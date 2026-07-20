#include <jwt-cpp/jwt.h>
#include <string>

void sign_rs256() {
    auto token = jwt::create().set_algorithm("RS256");
    token.sign(jwt::algorithm::rs256("", "", "", ""));
}

void sign_es256() {
    auto token = jwt::create().set_algorithm("ES256");
    token.sign(jwt::algorithm::es256("", "", "", ""));
}
