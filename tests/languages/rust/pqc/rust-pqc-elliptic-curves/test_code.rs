use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use p256::ecdsa::{signature::Signer as _, SigningKey as P256Key};
use rand::rngs::OsRng;

fn gen_p256_key() -> P256Key {
    P256Key::random(&mut OsRng)
}

fn gen_ed25519() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn sign_ed(key: &SigningKey, data: &[u8]) -> ed25519_dalek::Signature {
    key.sign(data)
}

fn verify_ed(key: &VerifyingKey, data: &[u8], sig: &ed25519_dalek::Signature) {
    key.verify(data, sig).unwrap();
}
