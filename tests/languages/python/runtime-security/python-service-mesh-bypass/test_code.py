import requests

def mesh_bypass(service_ip, port):
    url = "http://" + service_ip + ":" + port
    return requests.get(url)

def endpoint_bypass(endpoint):
    url = "http://" + endpoint
    return requests.get(url)
