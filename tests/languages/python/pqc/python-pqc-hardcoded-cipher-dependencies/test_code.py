import ssl

def restrict_ciphers():
    ctx = ssl.create_default_context()
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    return ctx
