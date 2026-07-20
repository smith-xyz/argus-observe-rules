use jsonwebtoken::{encode, Header, Algorithm};

fn sign_hs256(claims: serde_json::Value, key: &[u8]) -> String {
    let header = Header::new(Algorithm::HS256);
    encode(&header, &claims, key).unwrap()
}
