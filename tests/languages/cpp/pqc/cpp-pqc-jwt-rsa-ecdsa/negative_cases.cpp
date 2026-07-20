#include <jwt-cpp/jwt.h>

void sign_hs256() {
    auto token = jwt::create().set_algorithm("HS256");
}
