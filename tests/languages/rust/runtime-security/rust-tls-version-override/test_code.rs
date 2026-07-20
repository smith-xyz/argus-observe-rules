use native_tls::{Protocol, TlsConnector};
use rustls::{ClientConfig, ProtocolVersion, RootCertStore};

fn limit_rustls() {
    let roots = RootCertStore::empty();
    let _config = ClientConfig::builder()
        .with_safe_defaults()
        .with_protocol_versions(&[ProtocolVersion::TLSv1_2])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let _v1 = ProtocolVersion::TLSv1_1;
    let _v0 = ProtocolVersion::TLSv1_0;
}

fn limit_native_tls() {
    let _connector = TlsConnector::builder()
        .min_protocol_version(Some(Protocol::Tlsv12))
        .max_protocol_version(Some(Protocol::Tlsv11))
        .build()
        .unwrap();
    let _p = Protocol::Tlsv10;
}
