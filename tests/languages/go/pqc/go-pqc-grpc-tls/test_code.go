package main

import (
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Positive cases for go-pqc-grpc-tls

func newTLSCredentialsFromConfig(config *tls.Config) credentials.TransportCredentials {
	return credentials.NewTLS(config)
}

func newTLSCredentialsFromCert(cert tls.Certificate) credentials.TransportCredentials {
	return credentials.NewServerTLSFromCert(&cert)
}

func newTLSCredentialsFromFile(certFile, keyFile string) (credentials.TransportCredentials, error) {
	return credentials.NewServerTLSFromFile(certFile, keyFile)
}

func newClientTLSCredentialsFromFile(certFile, keyFile string) (credentials.TransportCredentials, error) {
	return credentials.NewClientTLSFromFile(certFile, "localhost")
}

func dialWithTransportCredentials(creds credentials.TransportCredentials) grpc.DialOption {
	return grpc.WithTransportCredentials(creds)
}

func serverWithCreds(creds credentials.TransportCredentials) grpc.ServerOption {
	return grpc.Creds(creds)
}

func dialInsecure() grpc.DialOption {
	return grpc.WithInsecure()
}

func setupGRPCServerAndClient() {
	config := &tls.Config{}
	creds := credentials.NewTLS(config)
	_ = grpc.NewServer(grpc.Creds(creds))
	_ = grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds))
}
