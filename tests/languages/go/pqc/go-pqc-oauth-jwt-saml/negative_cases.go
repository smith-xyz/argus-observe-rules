package main

import (
	"context"
	"fmt"
)

// Negative test cases - these should NOT be flagged

func stringLiteralsOnly() {
	msg := "oauth2.Config{ClientID: \"test\"}"
	desc := "saml.ServiceProvider metadata"
	issuer := "oidc.NewProvider context issuer"
	fmt.Println(msg, desc, issuer)
}

func unrelatedOAuthFlow(ctx context.Context) {
	// Generic HTTP client without oauth2/saml/oidc APIs
	type token struct {
		AccessToken string
	}
	t := token{AccessToken: "abc123"}
	_ = t
}

func customIdentityProvider() {
	type IdentityProvider struct {
		Name string
	}
	idp := IdentityProvider{Name: "local"}
	_ = idp
}
