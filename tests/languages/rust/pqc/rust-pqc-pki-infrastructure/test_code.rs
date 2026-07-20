use rcgen::{CertificateParams, generate_simple_self_signed, KeyPair};
use x509_parser::prelude::*;

fn build_cert() {
    let params = CertificateParams::default();
    let key = KeyPair::generate().unwrap();
    let _cert = params.self_signed(&key).unwrap();
}

fn self_signed() {
    let _cert = generate_simple_self_signed(vec!["example.com".into()]).unwrap();
}

fn parse_cert(data: &[u8]) {
    let (_, cert) = parse_x509_certificate(data).unwrap();
    let _pk = cert.public_key();
    let _validity = cert.validity();
}

fn parse_pem(data: &[u8]) {
    let _ = parse_x509_pem(data);
}
