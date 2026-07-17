package main

import (
	"github.com/golang-jwt/jwt/v5"
)

// Test cases for go-pqc-jwt-operations rule

func createJWT(method jwt.SigningMethod, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(method, claims)
	return token.SignedString([]byte("secret"))
}

func parseJWT(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
	return jwt.Parse(tokenString, keyFunc)
}

func parseJWTWithClaims(tokenString string, claims jwt.MapClaims, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, claims, keyFunc)
}
