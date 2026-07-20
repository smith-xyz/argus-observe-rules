#include <openssl/evp.h>

void sign_message(EVP_MD_CTX *ctx, EVP_PKEY *key) {
    EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key);
    EVP_DigestSign(ctx, nullptr, nullptr, nullptr, 0);
}

void verify_message(EVP_MD_CTX *ctx, EVP_PKEY *key) {
    EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, key);
}
