package main

import (
	"crypto/tls"
	"fmt"
)

// Negative cases - should NOT trigger go-pqc-ssh-server

func configureTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
}

func printServerStatus(status string) {
	fmt.Println("Server status:", status)
}

func unrelatedSSHReference() {
	message := "SSH server deployment complete"
	fmt.Println(message)
}
