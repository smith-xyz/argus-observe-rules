from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.backends import default_backend

def gen_ec_key():
    return ec.generate_private_key(ec.SECP256R1(), default_backend())

def gen_ed25519():
    return ed25519.Ed25519PrivateKey.generate()

def sign_ed(private_key, data):
    return private_key.sign(data)
