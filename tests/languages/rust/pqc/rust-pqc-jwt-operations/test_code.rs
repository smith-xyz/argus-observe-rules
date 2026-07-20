use jsonwebtoken::{decode, encode, Header, Validation};

fn create_token(claims: serde_json::Value, key: &[u8]) -> String {
    encode(&Header::default(), &claims, key).unwrap()
}

fn parse_token(token: &str, key: &[u8]) -> serde_json::Value {
    decode(token, key, &Validation::default()).unwrap().claims
}

fn parse_with_crate(token: &str, key: &[u8]) -> serde_json::Value {
    jsonwebtoken::decode(token, key, &Validation::default())
        .unwrap()
        .claims
}
