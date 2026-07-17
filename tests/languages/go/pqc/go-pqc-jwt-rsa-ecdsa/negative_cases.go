package main

import (
	"crypto/hmac"
	"crypto/sha256"
)

// Negative test cases - these should NOT be flagged

func hmacTokenSigning(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func compareSignatures(expected, actual []byte) bool {
	return hmac.Equal(expected, actual)
}

func tokenAlgorithmName() string {
	return "HS256"
}
