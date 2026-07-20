#include <openssl/ec.h>

void gen_ec_key(void) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key);
    EC_KEY_get0_group(key);
}

void ecdsa_ops(EC_KEY *key) {
    ECDSA_sign(0, NULL, 0, NULL, NULL, key);
    ECDSA_verify(0, NULL, 0, NULL, 0, key);
}
