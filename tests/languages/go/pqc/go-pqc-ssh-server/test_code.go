package main

import (
	"net"

	"golang.org/x/crypto/ssh"
)

func acceptSSHConnection(conn net.Conn, config *ssh.ServerConfig) {
	_, _, _, _ = ssh.NewServerConn(conn, config)
}

func createServerConfig() *ssh.ServerConfig {
	return &ssh.ServerConfig{
		NoClientAuth: true,
	}
}

func listenForSSH(network, addr string) (net.Listener, error) {
	return net.Listen(network, addr)
}

func addHostKey(config *ssh.ServerConfig, signer ssh.Signer) {
	config.AddHostKey(signer)
}

func signerFromKey(key interface{}) (ssh.Signer, error) {
	return ssh.NewSignerFromKey(key)
}

func signerFromSigner(signer ssh.Signer) (ssh.Signer, error) {
	return ssh.NewSignerFromSigner(signer)
}
