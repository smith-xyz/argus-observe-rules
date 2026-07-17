package gogrpctlsoverride

import (
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func secureGrpcCredentials() {
	creds := credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS12,
	})
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	_ = opts
}
