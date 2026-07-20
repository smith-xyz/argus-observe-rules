import ssl

def modern_tls():
    return ssl.create_default_context()
