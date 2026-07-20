use reqwest::Client;
use native_tls::{TlsConnector, TlsAcceptor};

fn bypass_reqwest() -> Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

fn bypass_native_tls() {
    let _connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let _acceptor = TlsAcceptor::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
}

fn bypass_rustls() {
    let _danger = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .dangerous();
}
