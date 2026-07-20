from cryptography import x509
from cryptography.hazmat.primitives import hashes

def load_cert(data):
    return x509.load_pem_x509_certificate(data)

def build_cert(builder, key):
  cert_builder = x509.CertificateBuilder()
  return cert_builder.sign(key, hashes.SHA256())

def load_csr(data):
    return x509.load_pem_x509_csr(data)

def issuer_name(dn):
    return x509.Name.from_rfc4514_string(dn)
