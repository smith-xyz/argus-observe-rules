package main

import (
	"net"
)

// Negative test cases - non-SSH client configuration patterns

func tcpDial(network, addr string) (net.Conn, error) {
	return net.Dial(network, addr)
}

func customClientConfig() map[string]string {
	return map[string]string{
		"user": "admin",
		"host": "example.com",
	}
}

func stringLiteralSSH() string {
	return "ssh.ClientConfig{User: \"admin\"}"
}

func hostKeyCallbackName() string {
	return "ssh.InsecureIgnoreHostKey should not match in strings"
}
