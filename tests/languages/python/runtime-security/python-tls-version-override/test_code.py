import ssl

def limit_tls():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    legacy = ssl.PROTOCOL_TLSv1_1
    return ctx, legacy
