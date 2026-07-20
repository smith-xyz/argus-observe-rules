def build_token_string(header, payload):
    return f"{header}.{payload}.sig"

def validate_format(token):
    return token.count(".") == 2
