from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from jwcrypto import jws

def rsa_sign(private_key, data):
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

def jws_sign(payload, key):
    token = jws.JWS(payload)
    token.add_signature(key, None, {"alg": "RS256"})
    return token.serialize()

def jws_verify(token):
    return jws.JWS.verify(token)
