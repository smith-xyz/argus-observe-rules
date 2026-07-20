use tonic::transport::{Channel, ClientTlsConfig, ServerTlsConfig};

async fn secure_tonic_channel() {
    let tls = ClientTlsConfig::new();
    let _channel = Channel::from_static("https://example.com:443")
        .tls_config(tls)
        .unwrap()
        .connect()
        .await;
}

async fn shared_channel(url: &str) {
    let _channel = Channel::from_shared(url.to_string()).unwrap().connect().await;
}

fn server_tls() -> ServerTlsConfig {
    ServerTlsConfig::new()
}

fn grpcio_channel(env: grpcio::Environment) {
    let builder = grpcio::ChannelBuilder::new(env);
    let _ = builder.secure_channel("example.com:443", grpcio::ChannelCredentials::default());
}
