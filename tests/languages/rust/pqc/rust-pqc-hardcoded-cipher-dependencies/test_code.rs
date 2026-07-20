use rustls::{cipher_suite, ClientConfig, ProtocolVersion, RootCertStore};

fn restrict_ciphers() {
    let roots = RootCertStore::empty();
    let _config = ClientConfig::builder()
        .with_cipher_suites(&[cipher_suite::TLS13_AES_256_GCM_SHA384])
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
}

fn restrict_tls_version() {
    let roots = RootCertStore::empty();
    let _config = ClientConfig::builder()
        .with_safe_defaults()
        .with_protocol_versions(&[ProtocolVersion::TLSv1_2])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
}
