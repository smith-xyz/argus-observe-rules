import jwt

def sign_rs256(payload, key):
    return jwt.encode(payload, key, algorithm="RS256")

def sign_es256(payload, key):
    return jwt.encode(payload, key, algorithm="ES256")

def verify_rs256(token, key):
    return jwt.decode(token, key, algorithms=["RS256"])
