use ssh2::Session;
use std::net::TcpStream;

fn ssh_connect(host: &str, port: u16, user: &str, pass: &str) -> Session {
    let tcp = TcpStream::connect(format!("{}:{}", host, port)).unwrap();
    let mut sess = Session::new().unwrap();
    sess.set_tcp_stream(tcp);
    sess.handshake().unwrap();
    sess.userauth_password(user, pass).unwrap();
    sess
}

fn ssh_pubkey(host: &str, user: &str, key_path: &str) {
    let tcp = TcpStream::connect(host).unwrap();
    let mut sess = ssh2::Session::new().unwrap();
    sess.set_tcp_stream(tcp);
    sess.handshake().unwrap();
    sess.userauth_pubkey_file(user, None, key_path, None).unwrap();
}
