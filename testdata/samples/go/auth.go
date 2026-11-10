package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
)

// LegacyAuth uses 2048-bit RSA (quantum-vulnerable)
type LegacyAuth struct {
	privateKey *rsa.PrivateKey
}

func NewLegacyAuth() (*LegacyAuth, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &LegacyAuth{privateKey: key}, nil
}

func (a *LegacyAuth) SignToken(msg []byte) ([]byte, error) {
	h := sha256.Sum256(msg)
	return rsa.SignPKCS1v15(rand.Reader, a.privateKey, 0, h[:])
}

// QuantumSafeTLSConfig configures hybrid post-quantum key exchange
func QuantumSafeTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
		},
	}
}
