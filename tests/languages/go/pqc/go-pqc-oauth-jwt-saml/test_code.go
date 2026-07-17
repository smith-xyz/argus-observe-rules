package main

import (
	"context"

	"github.com/crewjam/saml"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Test cases for go-pqc-oauth-jwt-saml rule

func oauthConfig() {
	config := oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "http://localhost/callback",
		Scopes:       []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://example.com/oauth/authorize",
			TokenURL: "https://example.com/oauth/token",
		},
	}
	_ = config
}

func oauthExchange(ctx context.Context, config *oauth2.Config, code string) {
	token, err := config.Exchange(ctx, code)
	_ = token
	_ = err
}

func oauthClient(ctx context.Context, config *oauth2.Config, token *oauth2.Token) {
	client := config.Client(ctx, token)
	_ = client
}

func samlServiceProvider() {
	sp := saml.ServiceProvider{
		MetadataURL: "https://example.com/saml/metadata",
	}
	_ = sp
}

func samlIdentityProvider() {
	idp := saml.IdentityProvider{
		MetadataURL: "https://example.com/idp/metadata",
	}
	_ = idp
}

func samlParseResponse(sp *saml.ServiceProvider, data []byte, possibleRequestIDs []string) {
	assertion, err := sp.ParseXMLResponse(data, possibleRequestIDs)
	_ = assertion
	_ = err
}

func oidcNewProvider(ctx context.Context) {
	provider, err := oidc.NewProvider(ctx, "https://accounts.example.com")
	_ = provider
	_ = err
}

func oidcVerifier(provider *oidc.Provider) {
	verifier := provider.Verifier(&oidc.Config{ClientID: "my-app"})
	_ = verifier
}

func oidcVerify(ctx context.Context, verifier *oidc.IDTokenVerifier, rawToken string) {
	token, err := verifier.Verify(ctx, rawToken)
	_ = token
	_ = err
}
