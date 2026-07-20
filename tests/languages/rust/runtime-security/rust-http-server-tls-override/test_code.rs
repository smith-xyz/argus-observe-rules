use axum::{Router, routing::get};
use std::net::SocketAddr;

async fn serve_tls(addr: SocketAddr, config: rustls::ServerConfig) {
    let app = Router::new().route("/", get(|| async { "ok" }));
    let _ = axum_server::bind_rustls(addr, config).serve(app.into_make_service()).await;
}

fn warp_tls() {
    let routes = warp::path("health").map(|| "ok");
    let _ = warp::serve(routes).tls();
}

fn hyper_rustls_builder() {
    let _builder = hyper_rustls::HttpsConnectorBuilder::new();
}
