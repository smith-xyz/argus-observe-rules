package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Negative test cases - these should NOT be flagged

type customToken struct {
	Header  map[string]string
	Payload map[string]interface{}
}

func buildTokenManually(header map[string]string, payload map[string]interface{}) string {
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	headerPart := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadPart := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return strings.Join([]string{headerPart, payloadPart, "signature"}, ".")
}

func validateTokenFormat(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 3
}

func printTokenInfo(token customToken) {
	fmt.Printf("token header: %v\n", token.Header)
}
