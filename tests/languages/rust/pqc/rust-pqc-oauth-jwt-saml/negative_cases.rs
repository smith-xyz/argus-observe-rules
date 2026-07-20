fn parse_bearer_token(header: &str) -> &str {
    header.strip_prefix("Bearer ").unwrap_or(header)
}
