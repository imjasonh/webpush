// Package keys provides VAPID key implementations.
package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

// FileSigner implements the Signer interface using keys stored on disk.
type FileSigner struct {
	privateKey *ecdsa.PrivateKey
	publicKey  []byte // uncompressed format
}

// NewFileSigner loads VAPID keys from a PEM file.
func NewFileSigner(privateKeyPath string) (*FileSigner, error) {
	data, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading private key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing EC private key: %w", err)
	}

	if privKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("key must be P-256 curve")
	}

	// Get public key in uncompressed format
	pubKey := elliptic.Marshal(privKey.Curve, privKey.X, privKey.Y)

	return &FileSigner{
		privateKey: privKey,
		publicKey:  pubKey,
	}, nil
}

// NewFileSignerFromBase64 creates a FileSigner from base64-encoded private key.
func NewFileSignerFromBase64(privateKeyB64 string) (*FileSigner, error) {
	privKeyBytes, err := base64.RawURLEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decoding private key: %w", err)
	}

	if len(privKeyBytes) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(privKeyBytes))
	}

	privKey := new(ecdsa.PrivateKey)
	privKey.Curve = elliptic.P256()
	privKey.D = new(big.Int).SetBytes(privKeyBytes)
	privKey.X, privKey.Y = privKey.Curve.ScalarBaseMult(privKeyBytes)

	// Get public key in uncompressed format
	pubKey := elliptic.Marshal(privKey.Curve, privKey.X, privKey.Y)

	return &FileSigner{
		privateKey: privKey,
		publicKey:  pubKey,
	}, nil
}

// Sign signs the given data using ECDSA and returns the signature in IEEE P1363 format.
func (s *FileSigner) Sign(_ context.Context, data []byte) ([]byte, error) {
	r, ss, err := ecdsa.Sign(rand.Reader, s.privateKey, data)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	// Convert to IEEE P1363 format (r || s, each 32 bytes)
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := ss.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	return sig, nil
}

// PublicKey returns the ECDSA public key in uncompressed format.
func (s *FileSigner) PublicKey() []byte {
	return s.publicKey
}

// PublicKeyBase64 returns the public key as a base64 URL-encoded string.
func (s *FileSigner) PublicKeyBase64() string {
	return base64.RawURLEncoding.EncodeToString(s.publicKey)
}

// GenerateKey generates a new ECDSA P-256 key pair and saves it to a PEM file.
func GenerateKey(path string) (*FileSigner, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	// Marshal the private key
	privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}

	// Create PEM block
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	}

	// Write to file
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		return nil, fmt.Errorf("writing private key: %w", err)
	}

	// Get public key in uncompressed format
	pubKey := elliptic.Marshal(privKey.Curve, privKey.X, privKey.Y)

	return &FileSigner{
		privateKey: privKey,
		publicKey:  pubKey,
	}, nil
}

// GenerateKeyPair generates a new key pair and returns both keys in base64 format.
func GenerateKeyPair() (privateKeyB64, publicKeyB64 string, err error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}

	// Private key as 32-byte big-endian integer
	privKeyBytes := privKey.D.Bytes()
	// Pad to 32 bytes if necessary
	paddedPrivKey := make([]byte, 32)
	copy(paddedPrivKey[32-len(privKeyBytes):], privKeyBytes)

	// Public key in uncompressed format
	pubKeyBytes := elliptic.Marshal(privKey.Curve, privKey.X, privKey.Y)

	return base64.RawURLEncoding.EncodeToString(paddedPrivKey),
		base64.RawURLEncoding.EncodeToString(pubKeyBytes),
		nil
}
