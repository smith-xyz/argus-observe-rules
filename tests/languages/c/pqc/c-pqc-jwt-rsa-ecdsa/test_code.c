#include <jwt.h>

void sign_rs256(jwt_t *jwt) {
    jwt_set_alg(jwt, JWT_ALG_RS256, NULL, 0);
}

void sign_es256(jwt_t *jwt) {
    jwt_set_alg(jwt, JWT_ALG_ES256, NULL, 0);
}

void sign_rs512(jwt_t *jwt) {
    jwt_set_alg(jwt, JWT_ALG_RS512, NULL, 0);
}
