const { Issuer } = require('openid-client');
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
