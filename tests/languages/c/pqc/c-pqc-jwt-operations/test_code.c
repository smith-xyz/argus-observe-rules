#include <jwt.h>

void jwt_encode_op(jwt_t *jwt, char *key) {
    jwt_encode(jwt, key, "HS256");
}

void jwt_decode_op(jwt_t **jwt, char *key) {
    jwt_decode(jwt, "token", 6, key, "HS256");
}

void jwt_create() {
    jwt_t *jwt = jwt_new();
}
