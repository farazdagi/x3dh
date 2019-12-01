// Package x3dh implements the X3DH key agreement protocol. See
// https://signal.org/docs/specifications/x3dh/.
package x3dh

import (
	"crypto"
	"io"
)

const (
	// PublicKeySize is the size of public keys used in this package, in bytes.
	PublicKeySize = 32

	// PrivateKeySize is the size of private keys used in this package, in bytes.
	PrivateKeySize = 32
)

type PublicKey [PublicKeySize]byte
type PrivateKey [PrivateKeySize]byte

// Curve represents either X25519 or X488 elliptic curve
type Curve interface {
	// GenerateKey generates private key using entropy from rand reader
	GenerateKey(reader io.Reader) (privateKey PrivateKey, err error)

	// PublicKey given user's private key, computes (on curve) corresponding public key.
	PublicKey(privateKey PrivateKey) (publicKey PublicKey)

	// ComputeSecret computes the shared secret using otherPublicKey as the other party's public key.
	ComputeSecret(privateKey PrivateKey, otherPublicKey PublicKey) []byte
}

// KeyExchange is a facade for DH key exchange functionality.
type KeyExchange struct {
	info  string      // string identifying the application
	curve Curve       // either X25519 or X448
	hash  crypto.Hash // 256 or 512-bit hash function (e.g. SHA256 or SHA512)
}

// New creates default key exchange implementation
func New() *KeyExchange {
	return NewKeyExchange("default", NewCurve25519(), crypto.SHA256)
}

// NewKeyExchange creates parametrized version of key exchange object.
func NewKeyExchange(info string, curve Curve, hash crypto.Hash) *KeyExchange {
	return &KeyExchange{
		info:  info,
		curve: curve,
		hash:  hash,
	}
}

// GenerateKeyPair generates a public/private key pair using entropy from rand reader.
// If reader is nil, crypto/rand.Reader will be used.
func (kex KeyExchange) GenerateKeyPair(reader io.Reader) (publicKey PublicKey, privateKey PrivateKey, err error) {
	privateKey, err = kex.curve.GenerateKey(reader)
	if err != nil {
		return
	}

	publicKey = kex.curve.PublicKey(privateKey)
	return
}

// Curve returns associated elliptic curve (either X25519 or X488)
func (kex KeyExchange) Curve() Curve {
	return kex.curve
}
