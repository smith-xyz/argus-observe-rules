import ssl

def secure_context():
    ctx = ssl.create_default_context()
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx
