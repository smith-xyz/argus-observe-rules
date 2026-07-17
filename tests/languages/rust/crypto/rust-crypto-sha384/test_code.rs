use ring::digest;
use sha2::{Sha384, Digest};
use openssl::hash::{hash, MessageDigest, Hasher};

fn ring_digest_patterns() {
    let data = b"test data";

    // Pattern: ring::digest::digest(&ring::digest::SHA384, $DATA) - Line 8
    let hash1 = digest::digest(&digest::SHA384, data);

    // Pattern: ring::digest::SHA384 - Line 11
    let algo = digest::SHA384;
}

fn sha2_crate_patterns() {
    let data = b"test data";

    // Pattern: sha2::Sha384::new() - Line 18
    let mut hasher1 = Sha384::new();

    // Pattern: sha2::Sha384::default() - Line 21
    let mut hasher2 = Sha384::default();

    // Pattern: sha2::Sha384::from($DATA) - Line 24
    let hasher3 = Sha384::from(data);

    // Pattern: let mut $HASHER = sha2::Sha384::new(); $HASHER.update($DATA); let $HASH = $HASHER.finalize(); - Line 27
    let mut hasher4 = Sha384::new();
    hasher4.update(data);
    let hash4 = hasher4.finalize();

    // Pattern: $HASHER.finalize_into($OUTPUT) - Line 33
    let mut hasher5 = Sha384::new();
    hasher5.update(data);
    let mut output = [0u8; 48];
    hasher5.finalize_into((&mut output).into());

    // Pattern: use sha2::{Sha384, Digest}; let mut $HASHER = Sha384::new(); $HASHER.update($DATA); $HASHER.finalize() - Line 39
    let mut hasher6 = Sha384::new();
    hasher6.update(data);
    let _hash6 = hasher6.finalize();
}

fn openssl_patterns() {
    let data = b"test data";

    // Pattern: openssl::hash::hash(openssl::hash::MessageDigest::sha384(), $DATA) - Line 48
    let hash1 = hash(MessageDigest::sha384(), data);

    // Pattern: let $MD = openssl::hash::MessageDigest::sha384(); openssl::hash::hash($MD, $DATA) - Line 51
    let md = MessageDigest::sha384();
    let hash2 = hash(md, data);

    // Pattern: openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha384()) - Line 55
    let mut hasher1 = Hasher::new(MessageDigest::sha384()).unwrap();

    // Pattern: let mut $HASHER = openssl::hash::Hasher::new(...); $HASHER.update($DATA); $HASHER.finish() - Line 58
    let mut hasher2 = Hasher::new(MessageDigest::sha384()).unwrap();
    hasher2.update(data).unwrap();
    let hash3 = hasher2.finish().unwrap();
}

fn digest_trait_patterns() {
    use digest::Digest;
    let data = b"test data";

    // Pattern: use digest::Digest; let mut $HASHER: Box<dyn Digest> = Box::new(sha2::Sha384::new()); ... - Line 67
    let mut hasher: Box<dyn Digest> = Box::new(Sha384::new());
    hasher.update(data);
    hasher.finalize();
}

async fn async_patterns() {
    let data = b"test data";

    // Pattern: async fn $FUNC() { sha2::Sha384::new(); ... } - Line 75
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize();
}
