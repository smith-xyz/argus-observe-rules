package main

import (
	"crypto/sha256"
	"fmt"
)

// Negative test cases - these should NOT be flagged

func hashForIntegrity(message []byte) [32]byte {
	return sha256.Sum256(message)
}

func compareDigests(expected, actual []byte) bool {
	if len(expected) != len(actual) {
		return false
	}
	for i := range expected {
		if expected[i] != actual[i] {
			return false
		}
	}
	return true
}

func describeSignatureAlgorithm(name string) {
	fmt.Printf("algorithm: %s\n", name)
}
