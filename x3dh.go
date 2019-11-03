// Package x3dh implements the X3DH key agreement protocol. See
// https://signal.org/docs/specifications/x3dh/.
package x3dh

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/curve25519"
)

const (
	// PublicKeyLen is the size of public keys used in this package, in bytes.
	PublicKeyLen = 32

	// PrivateKeyLen is the size of private keys used in this package, in bytes.
	PrivateKeyLen = 32
)

type PublicKey [PublicKeyLen]byte
type PrivateKey [PrivateKeyLen]byte

// KeyExchange defines methods necessary for X3DH key agreement.
type KeyExchange interface {
	// GenerateKey generates a public/private key pair using entropy from rand reader.
	// If reader is nil, crypto/rand.Reader will be used.
	GenerateKey(reader io.Reader) (PublicKey, PrivateKey, error)

	// PublicKey when given user's private key, computes (on curve) user's public key.
	PublicKey(PrivateKey) PublicKey

	// ComputeSecret computes the shared secret using otherPublicKey as the other
	// party's public key and returns the computed shared secret.
	ComputeSecret(privateKey PrivateKey, otherPublicKey PublicKey) []byte
}

// X25519 is key exchange based no X25519 curve.
type X25519 struct{}

// NewX25519 creates instance of X25519-based key exchange.
func NewX25519() KeyExchange {
	return new(X25519)
}

// GenerateKey generates a public/private key pair using entropy from rand reader.
// If reader is nil, crypto/rand.Reader will be used.
func (curve X25519) GenerateKey(reader io.Reader) (publicKey PublicKey, privateKey PrivateKey, err error) {
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

	curve25519.ScalarBaseMult((*[PublicKeyLen]byte)(&publicKey), (*[PrivateKeyLen]byte)(&privateKey))
	return
}

// PublicKey when given user's private key, computes (on curve) user's public key.
func (curve X25519) PublicKey(privateKey PrivateKey) (publicKey PublicKey) {
	curve25519.ScalarBaseMult((*[PublicKeyLen]byte)(&publicKey), (*[PrivateKeyLen]byte)(&privateKey))
	return
}

// ComputeSecret computes the shared secret using otherPublicKey as the other
// party's public key and returns the computed shared secret.
func (curve X25519) ComputeSecret(privateKey PrivateKey, otherPublicKey PublicKey) []byte {
	var sharedSecret [PrivateKeyLen]byte
	curve25519.ScalarMult(&sharedSecret, (*[PrivateKeyLen]byte)(&privateKey), (*[PublicKeyLen]byte)(&otherPublicKey))

	return sharedSecret[:]
}
