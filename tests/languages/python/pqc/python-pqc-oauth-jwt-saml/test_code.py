from authlib.integrations.requests_client import OAuth2Session
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from authlib.oauth2 import OAuth2Client

def oauth_flow(client_id, client_secret, code):
    session = OAuth2Session(client_id, client_secret)
    session.fetch_token("https://auth.example.com/token", code=code)
    return session.get("https://api.example.com/user")

def saml_auth(request_data, settings):
    auth = OneLogin_Saml2_Auth(request_data, settings)
    auth.login()
    return auth.process_response()

def oauth_client(client_id, client_secret):
    return OAuth2Client(client_id, client_secret)
