import requests
import httpx
import urllib3

def disable_validation():
    session = requests.Session()
    session.verify = False
    client = httpx.Client(verify=False)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return session, client
