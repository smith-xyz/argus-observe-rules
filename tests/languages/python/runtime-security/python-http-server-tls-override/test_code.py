import ssl
import http.server
import uvicorn

def serve_tls(sock, certfile, keyfile):
    wrapped = ssl.wrap_socket(sock, certfile=certfile, keyfile=keyfile)
    server = http.server.HTTPServer(("0.0.0.0", 8443), http.server.SimpleHTTPRequestHandler)
    uvicorn.run("app:app", ssl_keyfile=keyfile, ssl_certfile=certfile)
    return wrapped, server
