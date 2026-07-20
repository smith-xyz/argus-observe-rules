def parse_bearer_token(header):
    return header.replace("Bearer ", "")
