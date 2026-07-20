import requests
import httpx
import aiohttp
import urllib3

def custom_clients():
    session = requests.Session()
    client = httpx.Client(timeout=30)
    connector = aiohttp.TCPConnector()
    pool = urllib3.PoolManager(cert_reqs="CERT_REQUIRED")
    return session, client, connector, pool
