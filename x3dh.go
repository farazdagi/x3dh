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

// KeyExchangeParams defines set of parameters used for constructing key exchange object.
type KeyExchangeParams struct {
	info  string      // string identifying the application
	curve Curve       // either X25519 or X448
	hash  crypto.Hash // 256 or 512-bit hash function (e.g. SHA256 or SHA512)
}

// KeyExchange is a facade for DH key exchange functionality.
type KeyExchange struct {
	curve Curve
	hash  crypto.Hash
}

// New creates new key exchange object, using default params.
func New() *KeyExchange {
	params := KeyExchangeParams{
		info:  "default",
		curve: NewCurve25519(),
		hash:  crypto.SHA256,
	}

	return NewKeyExchange(params)
}

// NewKeyExchange creates parametrized version of key exchange object.
func NewKeyExchange(params KeyExchangeParams) *KeyExchange {
	return &KeyExchange{
		curve: params.curve,
		hash:  params.hash,
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
