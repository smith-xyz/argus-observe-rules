package gohttpservertlsoverride

import (
	"crypto/tls"
	"net/http"
)

func serverWithTLSConfigField() {
	customTLS := &tls.Config{MinVersion: tls.VersionTLS12}

	// Pattern: &http.Server with TLSConfig field - line 12
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: customTLS,
	}
	_ = server
}

func serverLiteralWithTLSConfig() {
	// Pattern: http.Server literal with TLSConfig - line 21
	server := http.Server{
		Addr: ":8443",
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	_ = server
}

func pointerServerAssignment() {
	customTLS := &tls.Config{MaxVersion: tls.VersionTLS12}
	server := &http.Server{Addr: ":8443"}

	// Pattern: pointer server TLSConfig assignment - line 34
	server.TLSConfig = customTLS
	_ = server
}

func valueServerAssignment() {
	customTLS := &tls.Config{MinVersion: tls.VersionTLS13}
	server := http.Server{Addr: ":8443"}

	// Pattern: value server TLSConfig assignment - line 43
	server.TLSConfig = customTLS
	_ = server
}

func inlineTLSConfig() {
	// Pattern: inline &tls.Config in Server - line 49
	server := &http.Server{
		Addr: ":8443",
		TLSConfig: &tls.Config{
			ServerName: "example.com",
		},
	}
	_ = server
}
