use ring::digest;
use sha2::{Sha256, Digest};
use openssl::hash::{hash, MessageDigest, Hasher};

fn ring_digest_patterns() {
    let data = b"test data";

    // Pattern: ring::digest::digest(&ring::digest::SHA256, $DATA) - Line 8
    let hash1 = digest::digest(&digest::SHA256, data);

    // Pattern: ring::digest::SHA256 - Line 11
    let algo = digest::SHA256;
}

fn sha2_crate_patterns() {
    let data = b"test data";

    // Pattern: sha2::Sha256::new() - Line 18
    let mut hasher1 = Sha256::new();

    // Pattern: sha2::Sha256::default() - Line 21
    let mut hasher2 = Sha256::default();

    // Pattern: sha2::Sha256::from($DATA) - Line 24
    let hasher3 = Sha256::from(data);

    // Pattern: let mut $HASHER = sha2::Sha256::new(); $HASHER.update($DATA); let $HASH = $HASHER.finalize(); - Line 27
    let mut hasher4 = Sha256::new();
    hasher4.update(data);
    let hash4 = hasher4.finalize();

    // Pattern: $HASHER.finalize_into($OUTPUT) - Line 33
    let mut hasher5 = Sha256::new();
    hasher5.update(data);
    let mut output = [0u8; 32];
    hasher5.finalize_into((&mut output).into());

    // Pattern: use sha2::{Sha256, Digest}; let mut $HASHER = Sha256::new(); $HASHER.update($DATA); - Line 39
    let mut hasher6 = Sha256::new();
    hasher6.update(data);
}

fn openssl_patterns() {
    let data = b"test data";

    // Pattern: openssl::hash::hash(openssl::hash::MessageDigest::sha256(), $DATA) - Line 46
    let hash1 = hash(MessageDigest::sha256(), data);

    // Pattern: let $MD = openssl::hash::MessageDigest::sha256(); openssl::hash::hash($MD, $DATA) - Line 49
    let md = MessageDigest::sha256();
    let hash4 = hash(md, data);

    // Pattern: openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256()) - Line 53
    let mut hasher1 = Hasher::new(MessageDigest::sha256()).unwrap();

    // Pattern: let mut $HASHER = openssl::hash::Hasher::new(...); $HASHER.update($DATA); $HASHER.finish() - Line 56
    let mut hasher2 = Hasher::new(MessageDigest::sha256()).unwrap();
    hasher2.update(data).unwrap();
    let hash5 = hasher2.finish().unwrap();
}

fn digest_trait_patterns() {
    use digest::Digest;
    let data = b"test data";

    // Pattern: use digest::Digest; let mut $HASHER: Box<dyn Digest> = Box::new(sha2::Sha256::new()); ... - Line 65
    let mut hasher: Box<dyn Digest> = Box::new(Sha256::new());
    hasher.update(data);
    hasher.finalize();
}

async fn async_patterns() {
    let data = b"test data";

    // Pattern: async fn $FUNC() { sha2::Sha256::new(); ... } - Line 73
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize();
}
