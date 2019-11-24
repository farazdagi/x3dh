package x3dh

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/curve25519"
)

// Curve25519 is representation of X25519 curve.
type Curve25519 struct{}

// NewCurve25519 creates instance of X25519 curve.
func NewCurve25519() Curve25519 {
	return Curve25519{}
}

// GenerateKey is used to generate private key on a given curve.
func (curve Curve25519) GenerateKey(reader io.Reader) (privateKey PrivateKey, err error) {
	if reader == nil {
		reader = rand.Reader
	}

	_, err = io.ReadFull(reader, privateKey[:])
	if err != nil {
		return
	}

	// see https://cr.yp.to/ecdh.html
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	return
}

// PublicKey given user's private key, computes (on curve) corresponding public key.
func (curve Curve25519) PublicKey(privateKey PrivateKey) (publicKey PublicKey) {
	curve25519.ScalarBaseMult((*[PublicKeySize]byte)(&publicKey), (*[PrivateKeySize]byte)(&privateKey))
	return
}

// ComputeSecret computes the shared secret using otherPublicKey as the other party's public key.
func (curve Curve25519) ComputeSecret(privateKey PrivateKey, otherPublicKey PublicKey) []byte {
	var sharedSecret [PrivateKeySize]byte
	curve25519.ScalarMult(&sharedSecret, (*[PrivateKeySize]byte)(&privateKey), (*[PublicKeySize]byte)(&otherPublicKey))

	return sharedSecret[:]
}
