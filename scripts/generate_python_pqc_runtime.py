#!/usr/bin/env python3
"""Generate Python PQC and runtime-security rules with tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_PQC = ROOT / "rules/languages/python/pqc"
RULES_RT = ROOT / "rules/languages/python/runtime-security"
TESTS = ROOT / "tests/languages/python"

RULES: dict[str, dict] = {
    # --- PQC ---
    "python-pqc-jwt-operations": {
        "category": "pqc",
        "yaml": """rules:
  - id: python-pqc-jwt-operations
    message: JWT token operations detected - verify PQC signature algorithm support
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: jwt.encode($PAYLOAD, $KEY, algorithm=$ALG)
          - pattern: jwt.decode($TOKEN, $KEY, algorithms=$ALGS)
          - pattern: jwt.decode($TOKEN, $KEY, algorithms=[$ALG])
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: JWT infrastructure may need updates for PQC signature algorithms
""",
        "test": '''import jwt

def create_token(payload, key):
    return jwt.encode(payload, key, algorithm="HS256")

def parse_token(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])

def parse_single(token, key):
    return jwt.decode(token, key, algorithms="HS256")
''',
        "negative": '''def build_token_string(header, payload):
    return f"{header}.{payload}.sig"

def validate_format(token):
    return token.count(".") == 2
''',
    },
    "python-pqc-jwt-rsa-ecdsa": {
        "category": "pqc",
        "yaml": """rules:
  - id: python-pqc-jwt-rsa-ecdsa
    message: JWT with RSA/ECDSA signatures detected - assess PQC signature algorithm support readiness
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: jwt.encode($PAYLOAD, $KEY, algorithm="RS256")
          - pattern: jwt.encode($PAYLOAD, $KEY, algorithm="RS384")
          - pattern: jwt.encode($PAYLOAD, $KEY, algorithm="RS512")
          - pattern: jwt.encode($PAYLOAD, $KEY, algorithm="ES256")
          - pattern: jwt.encode($PAYLOAD, $KEY, algorithm="ES384")
          - pattern: jwt.encode($PAYLOAD, $KEY, algorithm="ES512")
          - pattern: jwt.encode($PAYLOAD, $KEY, algorithm="PS256")
          - pattern: jwt.decode($TOKEN, $KEY, algorithms=["RS256"])
          - pattern: jwt.decode($TOKEN, $KEY, algorithms=["ES256"])
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: JWT signature algorithms catalogued - verify JWT library supports hybrid or PQC signature methods
""",
        "test": '''import jwt

def sign_rs256(payload, key):
    return jwt.encode(payload, key, algorithm="RS256")

def sign_es256(payload, key):
    return jwt.encode(payload, key, algorithm="ES256")

def verify_rs256(token, key):
    return jwt.decode(token, key, algorithms=["RS256"])
''',
        "negative": '''import jwt

def sign_hs256(payload, key):
    return jwt.encode(payload, key, algorithm="HS256")
''',
    },
    "python-pqc-oauth-jwt-saml": {
        "category": "pqc",
        "yaml": """rules:
  - id: python-pqc-oauth-jwt-saml
    message: OAuth/SAML/OIDC operations detected - assess identity protocol PQC signature readiness
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: OAuth2Session($CLIENT_ID, $CLIENT_SECRET)
          - pattern: $SESSION.fetch_token($URL, code=$CODE)
          - pattern: $SESSION.get($URL)
          - pattern: OneLogin_Saml2_Auth($REQUEST, $SETTINGS)
          - pattern: $AUTH.login()
          - pattern: $AUTH.process_response()
          - pattern: OAuth2Client($CLIENT_ID, $CLIENT_SECRET)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Identity protocol usage documented - verify OAuth/SAML/OIDC libraries support hybrid or PQC signature algorithms
""",
        "test": '''from authlib.integrations.requests_client import OAuth2Session
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
''',
        "negative": '''def parse_bearer_token(header):
    return header.replace("Bearer ", "")
''',
    },
    "python-pqc-ssh-client": {
        "category": "pqc",
        "yaml": """rules:
  - id: python-pqc-ssh-client
    message: SSH client configuration detected - evaluate PQC SSH algorithm support readiness
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: paramiko.SSHClient()
          - pattern: |
              $CLIENT = paramiko.SSHClient()
              ...
              $CLIENT.connect($HOSTNAME, ...)
          - pattern: $CLIENT.set_missing_host_key_policy(paramiko.AutoAddPolicy())
          - pattern: $CLIENT.set_missing_host_key_policy(paramiko.RejectPolicy())
          - pattern: paramiko.RSAKey.from_private_key_file($PATH)
          - pattern: paramiko.ECDSAKey.from_private_key_file($PATH)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: SSH client configuration documented - verify SSH library supports hybrid or PQC key exchange and authentication algorithms
""",
        "test": '''import paramiko

def ssh_connect(hostname, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname, username=username, password=password)
    return client

def load_key(path):
    return paramiko.RSAKey.from_private_key_file(path)
''',
        "negative": '''def format_ssh_command(host, user):
    return f"ssh {user}@{host}"
''',
    },
    "python-pqc-ssh-server": {
        "category": "pqc",
        "yaml": """rules:
  - id: python-pqc-ssh-server
    message: SSH server configuration detected - assess PQC SSH algorithm implementation capability
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: paramiko.Transport($SOCKET)
          - pattern: |
              $TRANSPORT = paramiko.Transport($SOCKET)
              ...
              $TRANSPORT.start_server(server=$SERVER)
          - pattern: $TRANSPORT.add_server_key($KEY)
          - pattern: paramiko.ServerInterface()
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: SSH server configuration catalogued - verify SSH server supports hybrid host keys and PQC algorithms
""",
        "test": '''import socket
import paramiko

class MyServer(paramiko.ServerInterface):
    pass

def start_ssh_server(sock, host_key):
    transport = paramiko.Transport(sock)
    transport.add_server_key(host_key)
    transport.start_server(server=MyServer())
    return transport
''',
        "negative": '''def describe_ssh_port(port):
    return f"SSH listens on {port}"
''',
    },
    "python-pqc-grpc-tls": {
        "category": "pqc",
        "yaml": """rules:
  - id: python-pqc-grpc-tls
    message: gRPC TLS configuration detected - evaluate hybrid TLS and certificate support capability
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: grpc.secure_channel($TARGET, $CREDS)
          - pattern: grpc.ssl_channel_credentials($ROOT_CERTS, $PRIVATE_KEY, $CERT_CHAIN)
          - pattern: grpc.insecure_channel($TARGET)
          - pattern: grpc.server($THREAD_POOL)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: gRPC TLS configuration documented - verify gRPC supports hybrid certificates and PQC cipher suites
""",
        "test": '''import grpc

def connect_secure(target, creds):
    return grpc.secure_channel(target, creds)

def connect_insecure(target):
    return grpc.insecure_channel(target)

def make_creds(root, key, chain):
    return grpc.ssl_channel_credentials(root, key, chain)
''',
        "negative": '''def grpc_endpoint(host, port):
    return f"{host}:{port}"
''',
    },
    "python-pqc-pki-infrastructure": {
        "category": "pqc",
        "yaml": """rules:
  - id: python-pqc-pki-infrastructure
    message: PKI and X.509 certificate operations detected - evaluate hybrid certificate infrastructure readiness
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: x509.load_pem_x509_certificate($DATA)
          - pattern: x509.load_der_x509_certificate($DATA)
          - pattern: x509.CertificateBuilder()
          - pattern: $BUILDER.sign($PRIVATE_KEY, $HASH_ALGORITHM)
          - pattern: x509.load_pem_x509_csr($DATA)
          - pattern: x509.Name.from_rfc4514_string($DN)
          - pattern: $CERT.public_key()
          - pattern: $CERT.verify_directly_issued_by($ISSUER)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: PKI infrastructure usage documented - verify certificate authorities and systems support hybrid or PQC certificates
""",
        "test": '''from cryptography import x509
from cryptography.hazmat.primitives import hashes

def load_cert(data):
    return x509.load_pem_x509_certificate(data)

def build_cert(builder, key):
  cert_builder = x509.CertificateBuilder()
  return cert_builder.sign(key, hashes.SHA256())

def load_csr(data):
    return x509.load_pem_x509_csr(data)

def issuer_name(dn):
    return x509.Name.from_rfc4514_string(dn)
''',
        "negative": '''def pem_header():
    return "-----BEGIN CERTIFICATE-----"
''',
    },
    "python-pqc-certificate-transparency": {
        "category": "pqc",
        "yaml": """rules:
  - id: python-pqc-certificate-transparency
    message: Certificate Transparency operations detected - ensure PQC certificate support
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: log_client.LogClient($URL, $FORMAT, $PUBKEY)
          - pattern: $CLIENT.get_sth()
          - pattern: $CLIENT.get_entries($START, $END)
          - pattern: $CLIENT.add_chain($CHAIN)
    metadata:
      category: pqc_readiness
      cwe: CWE-295
      impact: Certificate Transparency logs must support PQC certificates
""",
        "test": '''from ct.client import log_client

def query_ct_log(url, pubkey):
    client = log_client.LogClient(url, "json", pubkey)
    sth = client.get_sth()
    entries = client.get_entries(0, 10)
    return sth, entries
''',
        "negative": '''def log_url(base):
    return f"{base}/ct/v1/get-sth"
''',
    },
    "python-pqc-elliptic-curves": {
        "category": "pqc",
        "yaml": """rules:
  - id: python-pqc-elliptic-curves
    message: Elliptic curve cryptography identified - catalog for PQC migration assessment
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: ec.generate_private_key($CURVE, $BACKEND)
          - pattern: ec.SECP256R1()
          - pattern: ec.SECP384R1()
          - pattern: ec.SECP521R1()
          - pattern: ec.SECP256K1()
          - pattern: ed25519.Ed25519PrivateKey.generate()
          - pattern: ed25519.Ed25519PrivateKey.from_private_bytes($KEY)
          - pattern: $PRIVATE.sign($DATA)
          - pattern: $PUBLIC.verify($SIG, $DATA)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Elliptic curve usage documented for PQC transition planning - verify system supports algorithm substitution
""",
        "test": '''from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.backends import default_backend

def gen_ec_key():
    return ec.generate_private_key(ec.SECP256R1(), default_backend())

def gen_ed25519():
    return ed25519.Ed25519PrivateKey.generate()

def sign_ed(private_key, data):
    return private_key.sign(data)
''',
        "negative": '''def curve_name():
    return "P-256"
''',
    },
    "python-pqc-message-signing": {
        "category": "pqc",
        "yaml": """rules:
  - id: python-pqc-message-signing
    message: Message signing operations detected - evaluate PQC signature algorithm support capability
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: $PRIVATE.sign($DATA, padding.$PAD(), $HASH)
          - pattern: $PRIVATE.sign($DATA, $PAD, $HASH)
          - pattern: jws.JWS($PAYLOAD, $HEADER)
          - pattern: $JWS.add_signature($KEY, $HEADER)
          - pattern: jws.JWS.verify($TOKEN)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Message signing mechanisms documented - verify signing libraries support hybrid or PQC signature algorithms
""",
        "test": '''from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from jwcrypto import jws

def rsa_sign(private_key, data):
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

def jws_sign(payload, key):
    token = jws.JWS(payload)
    token.add_signature(key, None, {"alg": "RS256"})
    return token.serialize()

def jws_verify(token):
    return jws.JWS.verify(token)
''',
        "negative": '''def sign_string(data):
    return data + ".signed"
''',
    },
    "python-pqc-config-profile-dependencies": {
        "category": "pqc",
        "yaml": """rules:
  - id: python-pqc-config-profile-dependencies
    message: TLS/crypto configuration detected - verify PQC algorithm compatibility across system components
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: os.environ.get("OPENSSL_FIPS")
          - pattern: os.environ.get("FIPS_MODE")
          - pattern: os.environ.get("CRYPTOGRAPHY_OPENSSL_NO_LEGACY")
          - pattern: ssl.create_default_context()
          - pattern: grpc.secure_channel($TARGET, $CREDS)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Configuration may impose crypto requirements that create hard dependencies, causing system failures when PQC algorithms are enabled in mixed-version environments
""",
        "test": '''import os
import ssl
import grpc

def check_fips():
    return os.environ.get("OPENSSL_FIPS")

def tls_context():
    return ssl.create_default_context()

def grpc_connect(target, creds):
    return grpc.secure_channel(target, creds)
''',
        "negative": '''def app_name():
    return "myapp"
''',
    },
    "python-pqc-hardcoded-cipher-dependencies": {
        "category": "pqc",
        "yaml": """rules:
  - id: python-pqc-hardcoded-cipher-dependencies
    message: Hardcoded cipher suite or crypto algorithm configuration detected - may break when PQC algorithms are introduced
    severity: WARNING
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: |
              $CONTEXT.set_ciphers($CIPHERS)
          - pattern: |
              $CONTEXT.minimum_version = ssl.TLSVersion.TLSv1_2
          - pattern: |
              $CONTEXT.maximum_version = ssl.TLSVersion.TLSv1_2
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Hardcoded crypto configurations create dependencies that may break when PQC algorithms are enabled, especially in mixed-version environments
""",
        "test": '''import ssl

def restrict_ciphers():
    ctx = ssl.create_default_context()
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    return ctx
''',
        "negative": '''def default_context():
    import ssl
    return ssl.create_default_context()
''',
    },
    # --- Runtime security ---
    "python-tls-bypass": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: python-tls-bypass
    message: TLS security bypass detected - compromises transport security
    severity: ERROR
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: $CONTEXT.check_hostname = False
          - pattern: $CONTEXT.verify_mode = ssl.CERT_NONE
          - pattern: ssl._create_unverified_context()
          - pattern: requests.get($URL, verify=False)
          - pattern: requests.post($URL, verify=False, ...)
          - pattern: requests.Session().get($URL, verify=False)
          - pattern: httpx.get($URL, verify=False)
          - pattern: aiohttp.TCPConnector(ssl=False)
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: TLS bypasses eliminate transport security and enable MITM attacks
""",
        "test": '''import ssl
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
''',
        "negative": '''import ssl

def secure_context():
    ctx = ssl.create_default_context()
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx
''',
    },
    "python-tls-version-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: python-tls-version-override
    message: TLS version override detected - may block TLS 1.3 or weaken transport security
    severity: WARNING
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: $CONTEXT.maximum_version = ssl.TLSVersion.TLSv1_2
          - pattern: $CONTEXT.minimum_version = ssl.TLSVersion.TLSv1
          - pattern: ssl.PROTOCOL_TLSv1_2
          - pattern: ssl.PROTOCOL_TLSv1_1
          - pattern: ssl.PROTOCOL_TLSv1
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: TLS version restrictions may conflict with platform TLS profiles requiring TLS 1.3
""",
        "test": '''import ssl

def limit_tls():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    legacy = ssl.PROTOCOL_TLSv1_1
    return ctx, legacy
''',
        "negative": '''import ssl

def modern_tls():
    return ssl.create_default_context()
''',
    },
    "python-certificate-validation-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: python-certificate-validation-override
    message: Certificate validation override detected - breaks trust chain
    severity: ERROR
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: |
              $SESSION.verify = False
          - pattern: |
              $CLIENT = httpx.Client(verify=False)
          - pattern: |
              urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: Certificate validation override breaks trust chain and enables MITM attacks
""",
        "test": '''import requests
import httpx
import urllib3

def disable_validation():
    session = requests.Session()
    session.verify = False
    client = httpx.Client(verify=False)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return session, client
''',
        "negative": '''import requests

def secure_session():
    session = requests.Session()
    session.verify = "/etc/ssl/certs/ca.pem"
    return session
''',
    },
    "python-http-client-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: python-http-client-tls-override
    message: HTTP client with custom TLS config detected - may override platform TLS profile settings
    severity: WARNING
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: requests.Session()
          - pattern: httpx.Client($...ARGS)
          - pattern: aiohttp.ClientSession(connector=$CONNECTOR)
          - pattern: urllib3.PoolManager(cert_reqs=$REQ)
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: Custom TLS config in HTTP clients may override platform TLS profiles
""",
        "test": '''import requests
import httpx
import aiohttp
import urllib3

def custom_clients():
    session = requests.Session()
    client = httpx.Client(timeout=30)
    connector = aiohttp.TCPConnector()
    pool = urllib3.PoolManager(cert_reqs="CERT_REQUIRED")
    return session, client, connector, pool
''',
        "negative": '''def fetch_url(url):
    return url
''',
    },
    "python-http-server-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: python-http-server-tls-override
    message: HTTP server with custom TLS config detected - may override platform TLS profile settings
    severity: WARNING
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: ssl.wrap_socket($SOCK, ...)
          - pattern: http.server.HTTPServer($ADDR, $HANDLER)
          - pattern: uvicorn.run($APP, ssl_keyfile=$KEY, ssl_certfile=$CERT)
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: Custom TLS config in HTTP servers may override platform TLS profiles
""",
        "test": '''import ssl
import http.server
import uvicorn

def serve_tls(sock, certfile, keyfile):
    wrapped = ssl.wrap_socket(sock, certfile=certfile, keyfile=keyfile)
    server = http.server.HTTPServer(("0.0.0.0", 8443), http.server.SimpleHTTPRequestHandler)
    uvicorn.run("app:app", ssl_keyfile=keyfile, ssl_certfile=certfile)
    return wrapped, server
''',
        "negative": '''def listen_port(port):
    return port
''',
    },
    "python-grpc-tls-credential-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: python-grpc-tls-credential-override
    message: gRPC TLS credential override detected - may bypass service mesh security
    severity: ERROR
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: grpc.insecure_channel($TARGET)
          - pattern: grpc.local_channel_credentials()
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: gRPC credential override bypasses service mesh security and mTLS policies
""",
        "test": '''import grpc

def insecure_grpc(target):
    channel = grpc.insecure_channel(target)
    creds = grpc.local_channel_credentials()
    return channel, creds
''',
        "negative": '''def grpc_target(host, port):
    return f"{host}:{port}"
''',
    },
    "python-kubernetes-client-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: python-kubernetes-client-tls-override
    message: Kubernetes client TLS configuration override detected
    severity: WARNING
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: config.load_kube_config()
          - pattern: client.Configuration()
          - pattern: $CONFIG.verify_ssl = False
          - pattern: $CONFIG.assert_hostname = False
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: Kubernetes client TLS override can bypass cluster security policies
""",
        "test": '''from kubernetes import client, config

def k8s_insecure():
    config.load_kube_config()
    configuration = client.Configuration()
    configuration.verify_ssl = False
    configuration.assert_hostname = False
    return configuration
''',
        "negative": '''def cluster_name():
    return "production"
''',
    },
    "python-service-mesh-bypass": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: python-service-mesh-bypass
    message: Service mesh TLS bypass detected - communication outside mesh security
    severity: ERROR
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: |
              $URL = "http://" + $SERVICE_IP + ":" + $PORT
              ...
              requests.get($URL)
          - pattern: |
              $URL = "http://" + $ENDPOINT
              ...
              requests.get($URL)
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: Service mesh bypass eliminates mTLS protection and security observability
""",
        "test": '''import requests

def mesh_bypass(service_ip, port):
    url = "http://" + service_ip + ":" + port
    return requests.get(url)

def endpoint_bypass(endpoint):
    url = "http://" + endpoint
    return requests.get(url)
''',
        "negative": '''def mesh_url(host):
    return f"https://{host}"
''',
    },
    "python-reflection-basic-usage": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: python-reflection-basic-usage
    message: Basic reflection usage detected - mapping reflection landscape
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: type($OBJ)
          - pattern: isinstance($OBJ, $CLS)
          - pattern: getattr($OBJ, $NAME)
          - pattern: hasattr($OBJ, $NAME)
          - pattern: vars($OBJ)
          - pattern: dir($OBJ)
    metadata:
      category: reflection
      cwe: CWE-200
      impact: Basic reflection usage for landscape mapping
""",
        "test": '''def inspect_object(obj, cls, name):
    t = type(obj)
    ok = isinstance(obj, cls)
    attr = getattr(obj, name)
    present = hasattr(obj, name)
    v = vars(obj)
    names = dir(obj)
    return t, ok, attr, present, v, names
''',
        "negative": '''def object_id(obj):
    return id(obj)
''',
    },
    "python-reflection-advanced-patterns": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: python-reflection-advanced-patterns
    message: Advanced reflection patterns detected - landscape mapping
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: __import__($NAME)
          - pattern: importlib.import_module($NAME)
          - pattern: eval($EXPR)
          - pattern: exec($CODE)
    metadata:
      category: reflection
      cwe: CWE-20
      impact: Can bypass type safety and create security vulnerabilities
""",
        "test": '''import importlib

def dynamic_import(name, expr, code):
    mod = __import__(name)
    loaded = importlib.import_module(name)
    result = eval(expr)
    exec(code)
    return mod, loaded, result
''',
        "negative": '''def static_import():
    return "json"
''',
    },
    "python-reflection-structural-manipulation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: python-reflection-structural-manipulation
    message: Reflection structural manipulation detected - landscape mapping
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: setattr($OBJ, $NAME, $VALUE)
          - pattern: delattr($OBJ, $NAME)
          - pattern: globals()
          - pattern: locals()
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Runtime type manipulation can bypass compile-time safety
""",
        "test": '''def mutate(obj, name, value):
    setattr(obj, name, value)
    delattr(obj, name)
    g = globals()
    l = locals()
    return g, l
''',
        "negative": '''def read_attr(obj, name):
    return obj.__dict__.get(name)
''',
    },
    "python-reflection-type-assertion": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: python-reflection-type-assertion
    message: Reflection-based type assertion detected - potential type confusion risk
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: isinstance($OBJ, $TYPE)
          - pattern: issubclass($CLS, $BASE)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Type assertions from reflection can lead to type confusion vulnerabilities
""",
        "test": '''def check_types(obj, typ, cls, base):
    a = isinstance(obj, typ)
    b = issubclass(cls, base)
    return a, b
''',
        "negative": '''def type_name(obj):
    return obj.__class__.__name__
''',
    },
    "python-reflection-value-mutation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: python-reflection-value-mutation
    message: Reflection-based value mutation detected - landscape mapping
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: setattr($OBJ, $NAME, $VALUE)
          - pattern: object.__setattr__($OBJ, $NAME, $VALUE)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Reflection-based value mutation bypasses type safety and obscures data flow
""",
        "test": '''def mutate_values(obj, name, value):
    setattr(obj, name, value)
    object.__setattr__(obj, name, value)
''',
        "negative": '''def copy_value(value):
    return value
''',
    },
    "python-dynamic-method-invocation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: python-dynamic-method-invocation
    message: Dynamic method invocation patterns detected - landscape mapping
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: getattr($OBJ, $NAME)()
          - pattern: |
              $METHOD = getattr($OBJ, $NAME)
              ...
              $METHOD()
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Dynamic method calls can bypass authentication, authorization, and input validation
""",
        "test": '''def call_dynamic(obj, name):
    result = getattr(obj, name)()
    method = getattr(obj, name)
    out = method()
    return result, out
''',
        "negative": '''def call_direct(obj):
    return obj.run()
''',
    },
    "python-unsafe-pointer-operations": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: python-unsafe-pointer-operations
    message: Unsafe memory operations detected - landscape mapping
    severity: INFO
    languages:
      - python
    patterns:
      - pattern-either:
          - pattern: ctypes.cast($OBJ, $TYPE)
          - pattern: ctypes.POINTER($TYPE)
          - pattern: ctypes.memmove($DEST, $SRC, $COUNT)
          - pattern: ctypes.c_void_p($VALUE)
    metadata:
      category: memory_safety
      cwe: CWE-119
      impact: Unsafe memory operations can lead to memory corruption
""",
        "test": '''import ctypes

def unsafe_ops(buf, count):
    ptr = ctypes.cast(buf, ctypes.c_void_p)
    arr = ctypes.POINTER(ctypes.c_char)
    ctypes.memmove(buf, buf, count)
    void_p = ctypes.c_void_p(0)
    return ptr, arr, void_p
''',
        "negative": '''def safe_len(data):
    return len(data)
''',
    },
}


def write_files():
    for rule_id, spec in RULES.items():
        cat = spec["category"]
        rules_dir = RULES_PQC if cat == "pqc" else RULES_RT
        rules_dir.mkdir(parents=True, exist_ok=True)
        (rules_dir / f"{rule_id}.yml").write_text(spec["yaml"])

        test_dir = TESTS / cat / rule_id
        test_dir.mkdir(parents=True, exist_ok=True)
        (test_dir / "test_code.py").write_text(spec["test"])
        (test_dir / "negative_cases.py").write_text(spec["negative"])


def semgrep_findings(rule_id: str, test_file: Path) -> list[dict]:
    rule_file = None
    for base in (RULES_PQC, RULES_RT):
        candidate = base / f"{rule_id}.yml"
        if candidate.exists():
            rule_file = candidate
            break
    if not rule_file:
        return []
    result = subprocess.run(
        ["semgrep", "--config", str(rule_file), "--json", str(test_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in (0, 1):
        return []
    data = json.loads(result.stdout or "{}")
    return data.get("results", [])


def write_expected():
    for rule_id in RULES:
        cat = RULES[rule_id]["category"]
        test_dir = TESTS / cat / rule_id
        test_file = test_dir / "test_code.py"
        findings = []
        for item in semgrep_findings(rule_id, test_file):
            rid = item["check_id"].split(".")[-1]
            if rid != rule_id:
                continue
            findings.append(
                {
                    "file": "test_code.py",
                    "line": item["start"]["line"],
                    "rule_id": rule_id,
                    "message": item["extra"]["message"],
                }
            )
        findings.sort(key=lambda x: x["line"])
        lines = ["findings:"]
        for f in findings:
            lines.append(f"  - file: {f['file']}")
            lines.append(f"    line: {f['line']}")
            lines.append(f"    rule_id: {f['rule_id']}")
            lines.append(f'    message: "{f["message"]}"')
        lines.append("")
        lines.append("no_findings:")
        lines.append("  - negative_cases.py")
        (test_dir / "expected.yml").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    write_files()
    write_expected()
    print(f"Generated {len(RULES)} Python rules with tests")
