#include <openssl/ec.h>

void gen_ec_key() {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key);
}

void ecdsa_ops(EC_KEY *key) {
    ECDSA_sign(0, nullptr, 0, nullptr, nullptr, key);
    ECDSA_verify(0, nullptr, 0, nullptr, 0, key);
}
