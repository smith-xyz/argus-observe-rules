use std::env;
use rustls::ClientConfig;
use tonic::transport::Channel;

fn check_fips() {
    let _ = env::var("OPENSSL_FIPS");
    let _ = env::var("RUSTLS_FIPS");
    let _ = env::var("FIPS_MODE");
}

fn tls_config() {
    let _builder = ClientConfig::builder();
}

async fn grpc_connect() {
    let _ = Channel::from_static("https://example.com:443").connect().await;
}
