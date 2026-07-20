#include <openssl/evp.h>

void sign_message(EVP_MD_CTX *ctx, EVP_PKEY *key) {
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key);
    EVP_DigestSign(ctx, NULL, NULL, NULL, 0);
}

void sign_final(EVP_MD_CTX *ctx, EVP_PKEY *key) {
    EVP_SignFinal(ctx, NULL, NULL, key);
}

void verify_init(EVP_MD_CTX *ctx, EVP_PKEY *key) {
    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key);
}
