package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestNewFileSigner(t *testing.T) {
	// Generate a test key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Create temp file
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.pem")

	// Marshal and write
	privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	}

	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Test loading
	signer, err := NewFileSigner(keyPath)
	if err != nil {
		t.Fatalf("NewFileSigner() error = %v", err)
	}

	// Verify public key is 65 bytes (uncompressed P-256)
	if len(signer.PublicKey()) != 65 {
		t.Errorf("PublicKey() length = %d, want 65", len(signer.PublicKey()))
	}

	// Test signing
	data := []byte("test data hash")
	sig, err := signer.Sign(context.Background(), data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify signature is 64 bytes (r || s)
	if len(sig) != 64 {
		t.Errorf("Sign() signature length = %d, want 64", len(sig))
	}
}

func TestNewFileSignerFromBase64(t *testing.T) {
	// Generate a key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Get private key as 32-byte big-endian
	privKeyBytes := privKey.D.Bytes()
	paddedPrivKey := make([]byte, 32)
	copy(paddedPrivKey[32-len(privKeyBytes):], privKeyBytes)

	privKeyB64 := base64.RawURLEncoding.EncodeToString(paddedPrivKey)

	// Create signer
	signer, err := NewFileSignerFromBase64(privKeyB64)
	if err != nil {
		t.Fatalf("NewFileSignerFromBase64() error = %v", err)
	}

	// Verify public key
	if len(signer.PublicKey()) != 65 {
		t.Errorf("PublicKey() length = %d, want 65", len(signer.PublicKey()))
	}

	// Test signing
	data := []byte("test data hash")
	sig, err := signer.Sign(context.Background(), data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if len(sig) != 64 {
		t.Errorf("Sign() signature length = %d, want 64", len(sig))
	}
}

func TestGenerateKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "generated.pem")

	signer, err := GenerateKey(keyPath)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("Key file was not created")
	}

	// Verify public key
	if len(signer.PublicKey()) != 65 {
		t.Errorf("PublicKey() length = %d, want 65", len(signer.PublicKey()))
	}

	// Verify we can load the key back
	signer2, err := NewFileSigner(keyPath)
	if err != nil {
		t.Fatalf("NewFileSigner() error = %v", err)
	}

	if string(signer.PublicKey()) != string(signer2.PublicKey()) {
		t.Error("Loaded key doesn't match generated key")
	}
}

func TestGenerateKeyPair(t *testing.T) {
	privKeyB64, pubKeyB64, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	// Decode and verify private key length
	privKey, err := base64.RawURLEncoding.DecodeString(privKeyB64)
	if err != nil {
		t.Fatalf("DecodeString(privateKey) error = %v", err)
	}
	if len(privKey) != 32 {
		t.Errorf("Private key length = %d, want 32", len(privKey))
	}

	// Decode and verify public key length
	pubKey, err := base64.RawURLEncoding.DecodeString(pubKeyB64)
	if err != nil {
		t.Fatalf("DecodeString(publicKey) error = %v", err)
	}
	if len(pubKey) != 65 {
		t.Errorf("Public key length = %d, want 65", len(pubKey))
	}

	// Verify we can create a signer from the private key
	signer, err := NewFileSignerFromBase64(privKeyB64)
	if err != nil {
		t.Fatalf("NewFileSignerFromBase64() error = %v", err)
	}

	// Verify public keys match
	signerPubKeyB64 := signer.PublicKeyBase64()
	if signerPubKeyB64 != pubKeyB64 {
		t.Errorf("PublicKeyBase64() = %q, want %q", signerPubKeyB64, pubKeyB64)
	}
}

func TestNewFileSigner_InvalidFile(t *testing.T) {
	_, err := NewFileSigner("/nonexistent/path")
	if err == nil {
		t.Error("NewFileSigner() expected error for nonexistent file")
	}
}

func TestNewFileSigner_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "invalid.pem")

	if err := os.WriteFile(keyPath, []byte("not a pem file"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := NewFileSigner(keyPath)
	if err == nil {
		t.Error("NewFileSigner() expected error for invalid PEM")
	}
}

func TestNewFileSignerFromBase64_InvalidLength(t *testing.T) {
	// Too short
	_, err := NewFileSignerFromBase64("AAAA")
	if err == nil {
		t.Error("NewFileSignerFromBase64() expected error for invalid length")
	}
}
