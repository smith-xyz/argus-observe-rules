use reqwest::Client;

fn disable_validation() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap()
}

fn custom_verifier(verifier: std::sync::Arc<dyn rustls::client::danger::ServerCertVerifier>) {
    let _config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .dangerous()
        .set_certificate_verifier(verifier);
}
