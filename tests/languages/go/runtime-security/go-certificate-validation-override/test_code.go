package gocertvalidationoverride

import (
	"crypto/tls"
	"crypto/x509"
	"os"
)

type Webhook struct {
	ClientConfig struct {
		CABundle []byte
	}
}

func verifyPeerCertificateOverride() {
	config := &tls.Config{}

	// Pattern: VerifyPeerCertificate returns nil - line 20
	config.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		return nil
	}
	_ = config
}

func verifyConnectionOverride() {
	config := &tls.Config{}

	// Pattern: VerifyConnection returns nil - line 30
	config.VerifyConnection = func(state tls.ConnectionState) error {
		return nil
	}
	_ = config
}

func nilRootCAs() {
	config := &tls.Config{}

	// Pattern: RootCAs = nil - line 40
	config.RootCAs = nil
	_ = config
}

func nilClientCAs() {
	config := &tls.Config{}

	// Pattern: ClientCAs = nil - line 50
	config.ClientCAs = nil
	_ = config
}

func customCACertFromEnv() {
	config := &tls.Config{}

	// Pattern: CUSTOM_CA_CERT env override - line 58
	if customCert := os.Getenv("CUSTOM_CA_CERT"); customCert != "" {
		config.RootCAs = loadCertPool(customCert)
	}
	_ = config
}

func bypassCertPinningFromEnv() {
	config := &tls.Config{}

	// Pattern: BYPASS_CERT_PINNING env - line 68
	if bypass := os.Getenv("BYPASS_CERT_PINNING"); bypass == "true" {
		config.VerifyPeerCertificate = nil
	}
	_ = config
}

func nilCABundle() {
	config := struct {
		CABundle []byte
	}{}

	// Pattern: CABundle = nil - line 78
	config.CABundle = nil
	_ = config
}

func webhookCABundleNil() {
	webhook := Webhook{}

	// Pattern: webhook ClientConfig CABundle nil - line 86
	if shouldBypass() {
		webhook.ClientConfig.CABundle = nil
	}
	_ = webhook
}

func loadCertPool(path string) *x509.CertPool {
	return x509.NewCertPool()
}

func shouldBypass() bool {
	return true
}
