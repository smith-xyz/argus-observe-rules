package main

import (
	"github.com/golang-jwt/jwt/v5"
)

// Test cases for go-pqc-jwt-rsa-ecdsa rule

func rsaSigningMethods() []jwt.SigningMethod {
	return []jwt.SigningMethod{
		jwt.SigningMethodRS256,
		jwt.SigningMethodRS384,
		jwt.SigningMethodRS512,
	}
}

func ecdsaSigningMethods() []jwt.SigningMethod {
	return []jwt.SigningMethod{
		jwt.SigningMethodES256,
		jwt.SigningMethodES384,
		jwt.SigningMethodES512,
	}
}

func pssSigningMethods() []jwt.SigningMethod {
	return []jwt.SigningMethod{
		jwt.SigningMethodPS256,
		jwt.SigningMethodPS384,
		jwt.SigningMethodPS512,
	}
}

func createSignedToken(method jwt.SigningMethod, claims jwt.MapClaims, key interface{}) (string, error) {
	token := jwt.NewWithClaims(method, claims)
	return token.SignedString(key)
}
