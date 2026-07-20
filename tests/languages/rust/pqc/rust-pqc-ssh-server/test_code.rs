use russh::server;
use std::net::SocketAddr;

struct SshHandler;

#[async_trait::async_trait]
impl server::Server for SshHandler {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        Self
    }
}

async fn start_ssh_server(addr: SocketAddr) {
    let config = russh::server::Config::default();
    let _ = server::run(addr, config, SshHandler).await;
}

fn ssh_channel(sess: &ssh2::Session, host: &str, port: u16) {
    let _ = sess.channel_direct_tcpip(host, port, "127.0.0.1", 0);
}
