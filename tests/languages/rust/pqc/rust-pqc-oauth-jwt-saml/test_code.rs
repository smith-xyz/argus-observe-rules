use oauth2::{BasicClient, ClientId, ClientSecret, AuthUrl, TokenUrl, AuthorizationCode};
use openidconnect::{CoreClient, IssuerUrl, RedirectUrl};
use saml2::ServiceProvider;

async fn oauth_flow(client_id: &str, client_secret: &str, code: AuthorizationCode) {
    let client = BasicClient::new(
        ClientId::new(client_id.to_string()),
        Some(ClientSecret::new(client_secret.to_string())),
        AuthUrl::new("https://auth.example.com/authorize".to_string()).unwrap(),
        Some(TokenUrl::new("https://auth.example.com/token".to_string()).unwrap()),
    );
    client.set_auth_uri(AuthUrl::new("https://auth.example.com/authorize".to_string()).unwrap());
    let _token = client.exchange_code(code).request_async(oauth2::reqwest::async_http_client).await;
}

async fn oidc_flow() {
    let issuer = IssuerUrl::new("https://auth.example.com".to_string()).unwrap();
    let provider = openidconnect::core::CoreProviderMetadata::new(
        issuer.clone(),
        openidconnect::core::CoreJsonWebKeySet::new(vec![]),
    );
    let _client = CoreClient::from_provider(
        provider,
        ClientId::new("id".to_string()),
        Some(ClientSecret::new("secret".to_string())),
    )
    .set_redirect_uri(RedirectUrl::new("https://app.example.com/callback".to_string()).unwrap());
}

fn saml_auth(settings: saml2::Settings) {
    let sp = ServiceProvider::new(settings);
    let _ = sp.parse_response(b"<Response/>");
}
