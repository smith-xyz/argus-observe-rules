package main

import (
	"crypto/curve25519"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

// Positive cases for go-pqc-elliptic-curves

func useNISTCurves() {
	_ = elliptic.P224()
	_ = elliptic.P256()
	_ = elliptic.P384()
	_ = elliptic.P521()
}

func useCurveOperations() {
	curve := elliptic.P256()
	x1, y1 := big.NewInt(1), big.NewInt(2)
	x2, y2 := big.NewInt(3), big.NewInt(4)
	k := big.NewInt(5)

	_ = curve.Add(x1, y1, x2, y2)
	_ = curve.Double(x1, y1)
	_ = curve.ScalarMult(x1, y1, k)
	_ = curve.ScalarBaseMult(k)
}

func useCurve25519() {
	dst := make([]byte, 32)
	scalar := make([]byte, 32)
	point := make([]byte, 32)

	_ = curve25519.ScalarMult(dst, scalar, point)
	_ = curve25519.ScalarBaseMult(dst, scalar)
	_, _ = curve25519.X25519(scalar, point)
}

func useEd25519() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("message")
	sig := ed25519.Sign(priv, msg)
	_ = ed25519.Verify(pub, msg, sig)

	seed := make([]byte, ed25519.SeedSize)
	_ = ed25519.NewKeyFromSeed(seed)
}
