#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

void load_cert(BIO *bio) {
    X509 *cert = PEM_read_X509(bio, nullptr, nullptr, nullptr);
    X509_get_pubkey(cert);
}

void build_cert(X509 *cert, EVP_PKEY *key) {
    X509 *n = X509_new();
    X509_sign(n, key, EVP_sha256());
    X509_verify(cert, key);
}
