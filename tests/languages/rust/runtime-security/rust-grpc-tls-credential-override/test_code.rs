use tonic::transport::{Channel, Endpoint};
use grpcio::{ChannelBuilder, Environment};

async fn insecure_grpc() {
    let _channel = Channel::from_shared("http://example.com:50051".to_string())
        .unwrap()
        .connect()
        .await;
    let _endpoint = Endpoint::from_static("http://127.0.0.1:50051");
}

fn grpcio_insecure() {
    let env = Environment::new(1);
    let builder = ChannelBuilder::new(env);
    let _ = builder.connect("127.0.0.1:50051");
}
