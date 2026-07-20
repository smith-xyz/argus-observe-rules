import jwt

def sign_hs256(payload, key):
    return jwt.encode(payload, key, algorithm="HS256")
