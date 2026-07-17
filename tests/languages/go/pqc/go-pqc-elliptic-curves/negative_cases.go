package main

import (
	"crypto/sha256"
	"fmt"
)

// Negative cases - should NOT trigger go-pqc-elliptic-curves

func hashOnly(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func regularMath() int {
	return 1 + 2 + 3
}

func logMessage(msg string) {
	fmt.Println(msg)
}
