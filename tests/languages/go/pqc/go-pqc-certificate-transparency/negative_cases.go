package main

import (
	"crypto/x509"
)

// Negative test cases - these should NOT be flagged

func parseCertificatePEM(pemData []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(pemData)
}

func verifyCertificateChain(certs []*x509.Certificate) error {
	for i := 1; i < len(certs); i++ {
		if err := certs[i].CheckSignatureFrom(certs[i-1]); err != nil {
			return err
		}
	}
	return nil
}

func loadCertPoolFromFile(path string) (*x509.CertPool, error) {
	return x509.SystemCertPool()
}
