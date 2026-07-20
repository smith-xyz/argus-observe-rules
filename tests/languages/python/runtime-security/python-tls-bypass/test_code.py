import ssl
import requests
import httpx
import aiohttp

def bypass_ssl():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    unverified = ssl._create_unverified_context()
    requests.get("https://example.com", verify=False)
    httpx.get("https://example.com", verify=False)
    connector = aiohttp.TCPConnector(ssl=False)
    return ctx, unverified, connector
