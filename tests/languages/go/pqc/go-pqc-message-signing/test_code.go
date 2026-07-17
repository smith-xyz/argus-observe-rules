package main

import (
	"crypto"
	"crypto/rand"
	"io"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jws"
	"golang.org/x/crypto/openpgp"
)

func interfaceSign(priv crypto.Signer, digest []byte) ([]byte, error) {
	return priv.Sign(rand.Reader, digest, crypto.SHA256)
}

func joseSignerPattern(alg jose.SignatureAlgorithm, key interface{}) (jose.Signer, error) {
	return jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, nil)
}

func signerSignPattern(signer jose.Signer, payload []byte) (*jws.JSONWebSignature, error) {
	return signer.Sign(payload)
}

func jwsParseAndVerify(serialized string, algs []jose.SignatureAlgorithm, key interface{}) ([]byte, error) {
	object, err := jws.ParseSigned(serialized, algs)
	if err != nil {
		return nil, err
	}
	return object.Verify(key)
}

func openpgpDetachSign(w io.WriteCloser, message io.Reader, privateKey *openpgp.Entity) error {
	return openpgp.DetachSign(w, privateKey, message, nil)
}

func openpgpArmoredDetachSign(w io.WriteCloser, message io.Reader, privateKey *openpgp.Entity) error {
	return openpgp.ArmoredDetachSign(w, privateKey, message, nil)
}
