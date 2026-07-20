import requests

def secure_session():
    session = requests.Session()
    session.verify = "/etc/ssl/certs/ca.pem"
    return session
