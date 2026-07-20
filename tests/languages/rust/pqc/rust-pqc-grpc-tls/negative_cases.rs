fn grpc_endpoint(host: &str, port: u16) -> String {
    format!("{}:{}", host, port)
}
