use ring::signature;
use rsa::{pkcs1v15::SigningKey, RsaPrivateKey, signature::Signer};

fn ring_sign(private_key: &[u8], message: &[u8]) {
    let algo = &signature::RSA_PKCS1_SHA256;
    let _sig = signature::sign(algo, private_key, message);
}

fn ring_verify(public_key: &signature::UnparsedPublicKey, message: &[u8], sig: &[u8]) {
    signature::verify(public_key, message, sig).unwrap();
}

fn rsa_sign(key: RsaPrivateKey, data: &[u8]) -> Vec<u8> {
    let signing_key = SigningKey::<sha2::Sha256>::new(key);
    signing_key.sign(data)
}
