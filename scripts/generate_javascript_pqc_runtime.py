#!/usr/bin/env python3
"""Generate JavaScript PQC and runtime-security rules with tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_PQC = ROOT / "rules/languages/javascript/pqc"
RULES_RT = ROOT / "rules/languages/javascript/runtime-security"
TESTS = ROOT / "tests/languages/javascript"
EXT = "js"

RULES: dict[str, dict] = {
    "javascript-pqc-jwt-operations": {
        "category": "pqc",
        "yaml": """rules:
  - id: javascript-pqc-jwt-operations
    message: JWT token operations detected - verify PQC signature algorithm support
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: jwt.sign($PAYLOAD, $KEY, $OPTIONS)
          - pattern: jwt.verify($TOKEN, $KEY, $OPTIONS)
          - pattern: jwt.decode($TOKEN, $OPTIONS)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: JWT infrastructure may need updates for PQC signature algorithms
""",
        "test": """const jwt = require('jsonwebtoken');

function createToken(payload, key) {
  return jwt.sign(payload, key, { algorithm: 'HS256' });
}

function verifyToken(token, key) {
  return jwt.verify(token, key, { algorithms: ['HS256'] });
}

function decodeToken(token) {
  return jwt.decode(token, { complete: true });
}
""",
        "negative": """function buildToken(header, payload) {
  return `${header}.${payload}.sig`;
}
""",
    },
    "javascript-pqc-jwt-rsa-ecdsa": {
        "category": "pqc",
        "yaml": """rules:
  - id: javascript-pqc-jwt-rsa-ecdsa
    message: JWT with RSA/ECDSA signatures detected - assess PQC signature algorithm support readiness
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: "jwt.sign($PAYLOAD, $KEY, { algorithm: 'RS256' })"
          - pattern: "jwt.sign($PAYLOAD, $KEY, { algorithm: 'ES256' })"
          - pattern: "jwt.verify($TOKEN, $KEY, { algorithms: ['RS256'] })"
          - pattern: "jwt.verify($TOKEN, $KEY, { algorithms: ['ES256'] })"
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: JWT signature algorithms catalogued - verify JWT library supports hybrid or PQC signature methods
""",
        "test": """const jwt = require('jsonwebtoken');

function signRs256(payload, key) {
  return jwt.sign(payload, key, { algorithm: 'RS256' });
}

function signEs256(payload, key) {
  return jwt.sign(payload, key, { algorithm: 'ES256' });
}

function verifyRs256(token, key) {
  return jwt.verify(token, key, { algorithms: ['RS256'] });
}
""",
        "negative": """const jwt = require('jsonwebtoken');

function signHs256(payload, key) {
  return jwt.sign(payload, key, { algorithm: 'HS256' });
}
""",
    },
    "javascript-pqc-oauth-jwt-saml": {
        "category": "pqc",
        "yaml": """rules:
  - id: javascript-pqc-oauth-jwt-saml
    message: OAuth/SAML/OIDC operations detected - assess identity protocol PQC signature readiness
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: new Issuer($ISSUER)
          - pattern: $CLIENT.callbackParams($REQ)
          - pattern: $CLIENT.callback($REDIRECT_URI, $PARAMS)
          - pattern: new SamlAuth($OPTIONS)
          - pattern: $SAML.getAuthorizeUrlAsync($REQ, $HOST)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Identity protocol usage documented - verify OAuth/SAML/OIDC libraries support hybrid or PQC signature algorithms
""",
        "test": """const { Issuer } = require('openid-client');
const SamlAuth = require('saml2-js').SamlAuth;

async function oidcFlow(req) {
  const issuer = await Issuer.discover('https://auth.example.com');
  const client = new issuer.Client({ client_id: 'id', client_secret: 'secret' });
  const params = client.callbackParams(req);
  return client.callback('https://app.example.com/callback', params);
}

function samlFlow(req, host) {
  const saml = new SamlAuth({ audience: 'app', issuer: 'idp' });
  return saml.getAuthorizeUrlAsync(req, host);
}
""",
        "negative": """function parseBearer(header) {
  return header.replace('Bearer ', '');
}
""",
    },
    "javascript-pqc-ssh-client": {
        "category": "pqc",
        "yaml": """rules:
  - id: javascript-pqc-ssh-client
    message: SSH client configuration detected - evaluate PQC SSH algorithm support readiness
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: new Client()
          - pattern: |
              $CLIENT = new Client()
              ...
              $CLIENT.connect($CONFIG)
          - pattern: $CLIENT.on('hostkey', $HANDLER)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: SSH client configuration documented - verify SSH library supports hybrid or PQC key exchange and authentication algorithms
""",
        "test": """const { Client } = require('ssh2');

function sshConnect(config) {
  const client = new Client();
  client.on('hostkey', () => {});
  client.connect(config);
  return client;
}
""",
        "negative": """function sshCommand(host, user) {
  return `ssh ${user}@${host}`;
}
""",
    },
    "javascript-pqc-ssh-server": {
        "category": "pqc",
        "yaml": """rules:
  - id: javascript-pqc-ssh-server
    message: SSH server configuration detected - assess PQC SSH algorithm implementation capability
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: new Server($CONFIG, $HANDLER)
          - pattern: $SERVER.listen($PORT, $HOST, $CB)
          - pattern: $SERVER.on('connection', $HANDLER)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: SSH server configuration catalogued - verify SSH server supports hybrid host keys and PQC algorithms
""",
        "test": """const { Server } = require('ssh2');

function startServer(port, host) {
  const server = new Server({}, (client) => {
    client.on('authentication', () => {});
  });
  server.listen(port, host, () => {});
  return server;
}
""",
        "negative": """function sshPort(port) {
  return port;
}
""",
    },
    "javascript-pqc-grpc-tls": {
        "category": "pqc",
        "yaml": """rules:
  - id: javascript-pqc-grpc-tls
    message: gRPC TLS configuration detected - evaluate hybrid TLS and certificate support capability
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: new grpc.Client($TARGET, grpc.credentials.createSsl($ROOTS, $KEY, $CERT))
          - pattern: grpc.credentials.createInsecure()
          - pattern: grpc.Server($OPTIONS)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: gRPC TLS configuration documented - verify gRPC supports hybrid certificates and PQC cipher suites
""",
        "test": """const grpc = require('@grpc/grpc-js');

function secureClient(target, roots, key, cert) {
  return new grpc.Client(target, grpc.credentials.createSsl(roots, key, cert));
}

function insecureCreds() {
  return grpc.credentials.createInsecure();
}

function grpcServer() {
  return new grpc.Server();
}
""",
        "negative": """function endpoint(host, port) {
  return `${host}:${port}`;
}
""",
    },
    "javascript-pqc-pki-infrastructure": {
        "category": "pqc",
        "yaml": """rules:
  - id: javascript-pqc-pki-infrastructure
    message: PKI and X.509 certificate operations detected - evaluate hybrid certificate infrastructure readiness
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: new crypto.X509Certificate($DATA)
          - pattern: $CERT.checkIssued($ISSUER)
          - pattern: $CERT.verify($PUBLIC_KEY)
          - pattern: forge.pki.certificateFromPem($PEM)
          - pattern: forge.pki.certificationRequestFromPem($PEM)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: PKI infrastructure usage documented - verify certificate authorities and systems support hybrid or PQC certificates
""",
        "test": """const crypto = require('node:crypto');
const forge = require('node-forge');

function loadCert(data) {
  const cert = new crypto.X509Certificate(data);
  cert.checkIssued(cert);
  cert.verify(cert.publicKey);
  return cert;
}

function loadForgeCert(pem) {
  return forge.pki.certificateFromPem(pem);
}
""",
        "negative": """function pemHeader() {
  return '-----BEGIN CERTIFICATE-----';
}
""",
    },
    "javascript-pqc-certificate-transparency": {
        "category": "pqc",
        "yaml": """rules:
  - id: javascript-pqc-certificate-transparency
    message: Certificate Transparency operations detected - ensure PQC certificate support
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: $CERT.signedCertificateTimestampList
    metadata:
      category: pqc_readiness
      cwe: CWE-295
      impact: Certificate Transparency logs must support PQC certificates
""",
        "test": """const crypto = require('node:crypto');

function readScts(data) {
  const cert = new crypto.X509Certificate(data);
  return cert.signedCertificateTimestampList;
}
""",
        "negative": """function ctUrl(base) {
  return `${base}/ct/v1/get-sth`;
}
""",
    },
    "javascript-pqc-elliptic-curves": {
        "category": "pqc",
        "yaml": """rules:
  - id: javascript-pqc-elliptic-curves
    message: Elliptic curve cryptography identified - catalog for PQC migration assessment
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: crypto.createECDH($CURVE)
          - pattern: crypto.generateKeyPair('ec', $OPTIONS, $CALLBACK)
          - pattern: crypto.generateKeyPairSync('ed25519')
          - pattern: crypto.sign(null, $DATA, $PRIVATE_KEY)
          - pattern: crypto.verify(null, $DATA, $PUBLIC_KEY, $SIG)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Elliptic curve usage documented for PQC transition planning - verify system supports algorithm substitution
""",
        "test": """const crypto = require('node:crypto');

function ecdh(curve) {
  return crypto.createECDH(curve);
}

function genEcPair(cb) {
  return crypto.generateKeyPair('ec', { namedCurve: 'P-256' }, cb);
}

function genEd25519() {
  return crypto.generateKeyPairSync('ed25519');
}

function signData(data, key) {
  return crypto.sign(null, data, key);
}
""",
        "negative": """function curveName() {
  return 'P-256';
}
""",
    },
    "javascript-pqc-message-signing": {
        "category": "pqc",
        "yaml": """rules:
  - id: javascript-pqc-message-signing
    message: Message signing operations detected - evaluate PQC signature algorithm support capability
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: crypto.sign($ALGO, $DATA, $KEY)
          - pattern: crypto.verify($ALGO, $DATA, $KEY, $SIG)
          - pattern: new jose.SignJWT($PAYLOAD)
          - pattern: $JWT.sign($KEY)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Message signing mechanisms documented - verify signing libraries support hybrid or PQC signature algorithms
""",
        "test": """const crypto = require('node:crypto');
const jose = require('jose');

function rsaSign(data, key) {
  return crypto.sign('RSA-SHA256', data, key);
}

async function jwsSign(payload, key) {
  return await new jose.SignJWT(payload).setProtectedHeader({ alg: 'RS256' }).sign(key);
}
""",
        "negative": """function fakeSign(data) {
  return `${data}.signed`;
}
""",
    },
    "javascript-pqc-config-profile-dependencies": {
        "category": "pqc",
        "yaml": """rules:
  - id: javascript-pqc-config-profile-dependencies
    message: TLS/crypto configuration detected - verify PQC algorithm compatibility across system components
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: process.env.NODE_OPTIONS
          - pattern: process.env.OPENSSL_CONF
          - pattern: tls.createSecureContext($OPTIONS)
          - pattern: new grpc.Client($TARGET, $CREDS)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Configuration may impose crypto requirements that create hard dependencies
""",
        "test": """const tls = require('node:tls');
const grpc = require('@grpc/grpc-js');

function readConfig() {
  const opts = process.env.NODE_OPTIONS;
  const conf = process.env.OPENSSL_CONF;
  const ctx = tls.createSecureContext({ minVersion: 'TLSv1.2' });
  const client = new grpc.Client('localhost:50051', grpc.credentials.createInsecure());
  return { opts, conf, ctx, client };
}
""",
        "negative": """function appName() {
  return 'myapp';
}
""",
    },
    "javascript-pqc-hardcoded-cipher-dependencies": {
        "category": "pqc",
        "yaml": """rules:
  - id: javascript-pqc-hardcoded-cipher-dependencies
    message: Hardcoded cipher suite or crypto algorithm configuration detected - may break when PQC algorithms are introduced
    severity: WARNING
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: "tls.createSecureContext({ ciphers: $CIPHERS })"
          - pattern: |
              $CTX = tls.createSecureContext($OPTIONS)
              ...
              $CTX.setCiphers($CIPHERS)
    metadata:
      category: pqc_readiness
      cwe: CWE-327
      impact: Hardcoded crypto configurations create dependencies that may break when PQC algorithms are enabled
""",
        "test": """const tls = require('node:tls');

function restrictCiphers() {
  const ctx = tls.createSecureContext({ ciphers: 'ECDHE-RSA-AES128-GCM-SHA256' });
  ctx.setCiphers('HIGH:!aNULL');
  return ctx;
}
""",
        "negative": """const tls = require('node:tls');

function defaultContext() {
  return tls.createSecureContext();
}
""",
    },
    "javascript-tls-bypass": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: javascript-tls-bypass
    message: TLS security bypass detected - compromises transport security
    severity: ERROR
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: "rejectUnauthorized: false"
          - pattern: process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
          - pattern: $AGENT.options.rejectUnauthorized = false
          - pattern: "axios.get($URL, { httpsAgent: $AGENT })"
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: TLS bypasses eliminate transport security and enable MITM attacks
""",
        "test": """const https = require('node:https');
const axios = require('axios');

function bypassTls() {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  const agent = new https.Agent({ rejectUnauthorized: false });
  agent.options.rejectUnauthorized = false;
  return axios.get('https://example.com', { httpsAgent: agent });
}
""",
        "negative": """const https = require('node:https');

function secureAgent() {
  return new https.Agent({ rejectUnauthorized: true });
}
""",
    },
    "javascript-tls-version-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: javascript-tls-version-override
    message: TLS version override detected - may block TLS 1.3 or weaken transport security
    severity: WARNING
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: "minVersion: 'TLSv1'"
          - pattern: "maxVersion: 'TLSv1.2'"
          - pattern: "secureProtocol: 'TLSv1_2_method'"
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: TLS version restrictions may conflict with platform TLS profiles requiring TLS 1.3
""",
        "test": """const tls = require('node:tls');

function limitTls() {
  return tls.connect({
    host: 'example.com',
    port: 443,
    minVersion: 'TLSv1',
    maxVersion: 'TLSv1.2',
    secureProtocol: 'TLSv1_2_method',
  });
}
""",
        "negative": """const tls = require('node:tls');

function modernTls() {
  return tls.connect({ host: 'example.com', port: 443, minVersion: 'TLSv1.2' });
}
""",
    },
    "javascript-certificate-validation-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: javascript-certificate-validation-override
    message: Certificate validation override detected - breaks trust chain
    severity: ERROR
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: |
              checkServerIdentity: () => undefined
          - pattern: |
              checkServerIdentity: function($HOST, $CERT) { return undefined; }
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: Certificate validation override breaks trust chain and enables MITM attacks
""",
        "test": """const https = require('node:https');

function overrideCheck() {
  return https.request({
    hostname: 'example.com',
    checkServerIdentity: () => undefined,
  });
}
""",
        "negative": """const https = require('node:https');

function secureRequest() {
  return https.request({ hostname: 'example.com' });
}
""",
    },
    "javascript-http-client-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: javascript-http-client-tls-override
    message: HTTP client with custom TLS config detected - may override platform TLS profile settings
    severity: WARNING
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: new https.Agent($OPTIONS)
          - pattern: "axios.create({ httpsAgent: $AGENT })"
          - pattern: "fetch($URL, { agent: $AGENT })"
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: Custom TLS config in HTTP clients may override platform TLS profiles
""",
        "test": """const https = require('node:https');
const axios = require('axios');

function customClient() {
  const agent = new https.Agent({ keepAlive: true });
  const client = axios.create({ httpsAgent: agent });
  return client;
}
""",
        "negative": """function fetchUrl(url) {
  return url;
}
""",
    },
    "javascript-http-server-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: javascript-http-server-tls-override
    message: HTTP server with custom TLS config detected - may override platform TLS profile settings
    severity: WARNING
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: https.createServer($OPTIONS, $HANDLER)
          - pattern: tls.createServer($OPTIONS, $HANDLER)
    metadata:
      category: tls_runtime_security
      cwe: CWE-757
      impact: Custom TLS config in HTTP servers may override platform TLS profiles
""",
        "test": """const https = require('node:https');
const tls = require('node:tls');

function serveTls(options, handler) {
  const server = https.createServer(options, handler);
  const alt = tls.createServer(options, handler);
  return { server, alt };
}
""",
        "negative": """function listenPort(port) {
  return port;
}
""",
    },
    "javascript-grpc-tls-credential-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: javascript-grpc-tls-credential-override
    message: gRPC TLS credential override detected - may bypass service mesh security
    severity: ERROR
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: grpc.credentials.createInsecure()
          - pattern: new grpc.Client($TARGET, grpc.credentials.createInsecure())
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: gRPC credential override bypasses service mesh security and mTLS policies
""",
        "test": """const grpc = require('@grpc/grpc-js');

function insecureGrpc(target) {
  const creds = grpc.credentials.createInsecure();
  return new grpc.Client(target, grpc.credentials.createInsecure());
}
""",
        "negative": """function grpcTarget(host, port) {
  return `${host}:${port}`;
}
""",
    },
    "javascript-kubernetes-client-tls-override": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: javascript-kubernetes-client-tls-override
    message: Kubernetes client TLS configuration override detected
    severity: WARNING
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: new k8s.KubeConfig()
          - pattern: $KC.loadFromDefault()
          - pattern: $KC.loadFromCluster()
          - pattern: "skipTLSVerify: true"
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: Kubernetes client TLS override can bypass cluster security policies
""",
        "test": """const k8s = require('@kubernetes/client-node');

function k8sInsecure() {
  const kc = new k8s.KubeConfig();
  kc.loadFromDefault();
  kc.loadFromCluster();
  const cluster = { skipTLSVerify: true };
  return { kc, cluster };
}
""",
        "negative": """function clusterName() {
  return 'production';
}
""",
    },
    "javascript-service-mesh-bypass": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: javascript-service-mesh-bypass
    message: Service mesh TLS bypass detected - communication outside mesh security
    severity: ERROR
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: |
              $URL = 'http://' + $SERVICE_IP + ':' + $PORT
              ...
              fetch($URL)
    metadata:
      category: tls_runtime_security
      cwe: CWE-295
      impact: Service mesh bypass eliminates mTLS protection and security observability
""",
        "test": """async function meshBypass(serviceIp, port) {
  const url = 'http://' + serviceIp + ':' + port;
  return fetch(url);
}
""",
        "negative": """function meshUrl(host) {
  return `https://${host}`;
}
""",
    },
    "javascript-reflection-basic-usage": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: javascript-reflection-basic-usage
    message: Basic reflection usage detected - mapping reflection landscape
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: Reflect.get($OBJ, $KEY)
          - pattern: Reflect.has($OBJ, $KEY)
          - pattern: Reflect.ownKeys($OBJ)
          - pattern: typeof $OBJ
          - pattern: Object.keys($OBJ)
    metadata:
      category: reflection
      cwe: CWE-200
      impact: Basic reflection usage for landscape mapping
""",
        "test": """function inspect(obj, key) {
  const value = Reflect.get(obj, key);
  const has = Reflect.has(obj, key);
  const keys = Reflect.ownKeys(obj);
  const t = typeof obj;
  const own = Object.keys(obj);
  return { value, has, keys, t, own };
}
""",
        "negative": """function objectId(obj) {
  return obj.id;
}
""",
    },
    "javascript-reflection-advanced-patterns": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: javascript-reflection-advanced-patterns
    message: Advanced reflection patterns detected - landscape mapping
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: eval($EXPR)
          - pattern: new Function($ARGS, $BODY)
          - pattern: import($MODULE)
    metadata:
      category: reflection
      cwe: CWE-20
      impact: Can bypass type safety and create security vulnerabilities
""",
        "test": """async function dynamic(expr, args, body, mod) {
  const result = eval(expr);
  const fn = new Function(args, body);
  const loaded = await import(mod);
  return { result, fn, loaded };
}
""",
        "negative": """function staticName() {
  return 'json';
}
""",
    },
    "javascript-reflection-structural-manipulation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: javascript-reflection-structural-manipulation
    message: Reflection structural manipulation detected - landscape mapping
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: Reflect.set($OBJ, $KEY, $VALUE)
          - pattern: Reflect.deleteProperty($OBJ, $KEY)
          - pattern: Object.defineProperty($OBJ, $KEY, $DESC)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Runtime type manipulation can bypass compile-time safety
""",
        "test": """function mutate(obj, key, value) {
  Reflect.set(obj, key, value);
  Reflect.deleteProperty(obj, key);
  Object.defineProperty(obj, key, { value });
}
""",
        "negative": """function read(obj, key) {
  return obj[key];
}
""",
    },
    "javascript-reflection-type-assertion": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: javascript-reflection-type-assertion
    message: Reflection-based type assertion detected - potential type confusion risk
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: $OBJ instanceof $TYPE
          - pattern: Object.prototype.toString.call($OBJ)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Type assertions from reflection can lead to type confusion vulnerabilities
""",
        "test": """function checkTypes(obj, type) {
  const isType = obj instanceof type;
  const tag = Object.prototype.toString.call(obj);
  return { isType, tag };
}
""",
        "negative": """function typeName(obj) {
  return obj.constructor.name;
}
""",
    },
    "javascript-reflection-value-mutation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: javascript-reflection-value-mutation
    message: Reflection-based value mutation detected - landscape mapping
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: Reflect.set($OBJ, $KEY, $VALUE)
          - pattern: Object.assign($TARGET, $SOURCE)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Reflection-based value mutation bypasses type safety and obscures data flow
""",
        "test": """function mutateValues(target, source, key, value) {
  Reflect.set(target, key, value);
  Object.assign(target, source);
}
""",
        "negative": """function copy(value) {
  return value;
}
""",
    },
    "javascript-dynamic-method-invocation": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: javascript-dynamic-method-invocation
    message: Dynamic method invocation patterns detected - landscape mapping
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: $OBJ[$METHOD]($...ARGS)
          - pattern: |
              $FN = $OBJ[$METHOD]
              ...
              $FN($...ARGS)
    metadata:
      category: reflection
      cwe: CWE-470
      impact: Dynamic method calls can bypass authentication, authorization, and input validation
""",
        "test": """function callDynamic(obj, method, arg) {
  const direct = obj[method](arg);
  const fn = obj[method];
  const indirect = fn(arg);
  return { direct, indirect };
}
""",
        "negative": """function callDirect(obj) {
  return obj.run();
}
""",
    },
    "javascript-unsafe-pointer-operations": {
        "category": "runtime-security",
        "yaml": """rules:
  - id: javascript-unsafe-pointer-operations
    message: Unsafe memory operations detected - landscape mapping
    severity: INFO
    languages:
      - javascript
    patterns:
      - pattern-either:
          - pattern: new ArrayBuffer($SIZE)
          - pattern: new SharedArrayBuffer($SIZE)
          - pattern: new DataView($BUFFER)
          - pattern: new Uint8Array($BUFFER)
    metadata:
      category: memory_safety
      cwe: CWE-119
      impact: Low-level buffer operations require careful bounds checking
""",
        "test": """function bufferOps(size, buffer) {
  const ab = new ArrayBuffer(size);
  const sab = new SharedArrayBuffer(size);
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  return { ab, sab, view, bytes };
}
""",
        "negative": """function safeLen(data) {
  return data.length;
}
""",
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
        (test_dir / f"test_code.{EXT}").write_text(spec["test"])
        (test_dir / f"negative_cases.{EXT}").write_text(spec["negative"])


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
        test_file = test_dir / f"test_code.{EXT}"
        findings = []
        for item in semgrep_findings(rule_id, test_file):
            rid = item["check_id"].split(".")[-1]
            if rid != rule_id:
                continue
            findings.append(
                {
                    "file": f"test_code.{EXT}",
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
        lines.append(f"  - negative_cases.{EXT}")
        (test_dir / "expected.yml").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    write_files()
    write_expected()
    print(f"Generated {len(RULES)} JavaScript rules with tests")
