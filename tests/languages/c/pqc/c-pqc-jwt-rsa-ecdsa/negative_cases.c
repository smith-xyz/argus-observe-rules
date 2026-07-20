#include <jwt.h>

void sign_hs256(jwt_t *jwt) {
    jwt_set_alg(jwt, JWT_ALG_HS256, NULL, 0);
}
