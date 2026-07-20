fn build_token_string(header: &str, payload: &str) -> String {
    format!("{}.{}.sig", header, payload)
}

fn validate_format(token: &str) -> bool {
    token.matches('.').count() == 2
}
