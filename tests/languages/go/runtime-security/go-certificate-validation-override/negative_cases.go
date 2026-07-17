package gocertvalidationoverride

import (
	"crypto/tls"
	"crypto/x509"
	"os"
)

func secureCertificateValidation() {
	config := &tls.Config{
		RootCAs: x509.NewCertPool(),
	}

	config.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) == 0 {
			return x509.CertificateInvalidError{}
		}
		return nil
	}

	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return x509.CertificateInvalidError{}
		}
		return nil
	}

	_ = os.Getenv("UNRELATED_ENV")
	_ = config
}
