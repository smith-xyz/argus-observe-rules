use jsonwebtoken::{encode, decode, Header, Validation, Algorithm};

fn sign_rs256(claims: serde_json::Value, key: &[u8]) -> String {
    let header = Header::new(Algorithm::RS256);
    encode(&header, &claims, key).unwrap()
}

fn sign_es256(claims: serde_json::Value, key: &[u8]) -> String {
    let header = Header::new(Algorithm::ES256);
    encode(&header, &claims, key).unwrap()
}

fn verify_rs256(token: &str, key: &[u8]) -> serde_json::Value {
    let validation = Validation::new(Algorithm::RS256);
    decode(token, key, &validation).unwrap().claims
}
