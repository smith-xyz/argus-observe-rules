#include <jwt-cpp/jwt.h>
#include <string>

void create_token() {
    auto token = jwt::create().set_payload_claim("sub", jwt::claim(std::string("user")));
    token.sign(jwt::algorithm::hs256{"secret"});
}

void parse_token() {
    auto decoded = jwt::decode("header.payload.sig");
}
