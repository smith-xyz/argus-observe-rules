import jwt

def create_token(payload, key):
    return jwt.encode(payload, key, algorithm="HS256")

def parse_token(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])

def parse_single(token, key):
    return jwt.decode(token, key, algorithms="HS256")
