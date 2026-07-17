package main

import (
	"net"

	"golang.org/x/crypto/ssh"
)

// Test cases for go-pqc-ssh-client rule

func sshClientConfig() *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.Password("secret"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

func sshDial(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	return ssh.Dial(network, addr, config)
}

func sshNewClientConn(conn net.Conn, addr string, config *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	return ssh.NewClientConn(conn, addr, config)
}

func sshParsePrivateKey(pemBytes []byte) (ssh.Signer, error) {
	return ssh.ParsePrivateKey(pemBytes)
}

func sshParsePublicKey(key interface{}) (ssh.PublicKey, error) {
	return ssh.ParsePublicKey(key.([]byte))
}

func sshNewPublicKey(key interface{}) (ssh.PublicKey, error) {
	return ssh.NewPublicKey(key)
}

func sshInsecureIgnoreHostKey() ssh.HostKeyCallback {
	return ssh.InsecureIgnoreHostKey()
}

func sshFixedHostKey(key ssh.PublicKey) ssh.HostKeyCallback {
	return ssh.FixedHostKey(key)
}

func sshHostKeyCallback(callback ssh.HostKeyCallback) ssh.HostKeyCallback {
	return ssh.HostKeyCallback(callback)
}
