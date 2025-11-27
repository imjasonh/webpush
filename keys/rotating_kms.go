package keys

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

// RotatingKMSSigner implements key rotation using Google Cloud KMS.
// It manages multiple KMS key versions with a shared KMS client, which is
// more efficient than creating separate KMSSigner instances for each key.
//
// When a VAPID key is rotated, existing browser subscriptions are invalidated
// because they are tied to the applicationServerKey (VAPID public key).
// The RotatingKMSSigner helps manage this transition by:
//  1. Signing all new operations with the current key version
//  2. Tracking previous key versions so you can identify which subscriptions need re-subscription
//  3. Providing all public keys to help migrate subscriptions
type RotatingKMSSigner struct {
	mu       sync.RWMutex
	client   *kms.KeyManagementClient
	current  *kmsKeyVersion
	previous []*kmsKeyVersion
}

// kmsKeyVersion holds information about a single KMS key version.
type kmsKeyVersion struct {
	keyName   string
	publicKey []byte // uncompressed format
}

// NewRotatingKMSSigner creates a new rotating KMS signer with the given current key version.
// keyName should be in the format:
// projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}/cryptoKeyVersions/{version}
func NewRotatingKMSSigner(ctx context.Context, keyName string) (*RotatingKMSSigner, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating KMS client: %w", err)
	}

	keyVersion, err := fetchKMSKeyVersion(ctx, client, keyName)
	if err != nil {
		client.Close()
		return nil, err
	}

	return &RotatingKMSSigner{
		client:   client,
		current:  keyVersion,
		previous: nil,
	}, nil
}

// fetchKMSKeyVersion fetches the public key for a KMS key version.
func fetchKMSKeyVersion(ctx context.Context, client *kms.KeyManagementClient, keyName string) (*kmsKeyVersion, error) {
	resp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: keyName,
	})
	if err != nil {
		return nil, fmt.Errorf("getting public key for %s: %w", keyName, err)
	}

	// Parse the PEM-encoded public key
	block, _ := pem.Decode([]byte(resp.Pem))
	if block == nil {
		return nil, fmt.Errorf("failed to parse public key PEM for %s", keyName)
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key for %s: %w", keyName, err)
	}

	ecdsaPubKey, ok := pubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key %s is not ECDSA", keyName)
	}

	if ecdsaPubKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("key %s must be P-256 curve", keyName)
	}

	// Convert to uncompressed format
	pubKey := elliptic.Marshal(ecdsaPubKey.Curve, ecdsaPubKey.X, ecdsaPubKey.Y)

	return &kmsKeyVersion{
		keyName:   keyName,
		publicKey: pubKey,
	}, nil
}

// Sign signs the given data using the current KMS key version.
func (r *RotatingKMSSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	r.mu.RLock()
	keyName := r.current.keyName
	r.mu.RUnlock()

	resp, err := r.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: keyName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: data,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("signing with KMS: %w", err)
	}

	// KMS returns DER-encoded signature, convert to IEEE P1363 format
	return kmsDerToP1363(resp.Signature)
}

// kmsDerToP1363 converts a DER-encoded ECDSA signature to IEEE P1363 format.
func kmsDerToP1363(der []byte) ([]byte, error) {
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, fmt.Errorf("parsing DER signature: %w", err)
	}

	// Convert to IEEE P1363 format (r || s, each 32 bytes for P-256)
	result := make([]byte, 64)
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	copy(result[32-len(rBytes):32], rBytes)
	copy(result[64-len(sBytes):64], sBytes)

	return result, nil
}

// PublicKey returns the current ECDSA public key in uncompressed format.
func (r *RotatingKMSSigner) PublicKey() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current.publicKey
}

// PublicKeyBase64 returns the current public key as a base64 URL-encoded string.
func (r *RotatingKMSSigner) PublicKeyBase64() string {
	return base64.RawURLEncoding.EncodeToString(r.PublicKey())
}

// Rotate adds a new KMS key version as the current key and moves the old current key
// to the previous keys list. The new key will be used for all new signing operations.
//
// After rotation, existing subscriptions created with the old key will
// need to be re-subscribed by clients using the new applicationServerKey.
func (r *RotatingKMSSigner) Rotate(ctx context.Context, newKeyName string) error {
	keyVersion, err := fetchKMSKeyVersion(ctx, r.client, newKeyName)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Move current to previous
	r.previous = append([]*kmsKeyVersion{r.current}, r.previous...)
	r.current = keyVersion
	return nil
}

// AddPreviousKey adds an existing KMS key version to the previous keys list.
// This is useful when initializing the rotating signer with existing keys
// that have subscriptions associated with them.
func (r *RotatingKMSSigner) AddPreviousKey(ctx context.Context, keyName string) error {
	keyVersion, err := fetchKMSKeyVersion(ctx, r.client, keyName)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.previous = append(r.previous, keyVersion)
	return nil
}

// PreviousKeys returns all previous public keys in order from most recent to oldest.
func (r *RotatingKMSSigner) PreviousKeys() [][]byte {
	r.mu.RLock()
	defer r.mu.RUnlock()

	keys := make([][]byte, len(r.previous))
	for i, kv := range r.previous {
		keys[i] = kv.publicKey
	}
	return keys
}

// PreviousKeysBase64 returns all previous public keys as base64 URL-encoded strings.
func (r *RotatingKMSSigner) PreviousKeysBase64() []string {
	keys := r.PreviousKeys()
	b64Keys := make([]string, len(keys))
	for i, key := range keys {
		b64Keys[i] = base64.RawURLEncoding.EncodeToString(key)
	}
	return b64Keys
}

// AllKeys returns all public keys (current and previous) with current first.
func (r *RotatingKMSSigner) AllKeys() [][]byte {
	r.mu.RLock()
	defer r.mu.RUnlock()

	keys := make([][]byte, 1+len(r.previous))
	keys[0] = r.current.publicKey
	for i, kv := range r.previous {
		keys[i+1] = kv.publicKey
	}
	return keys
}

// AllKeysBase64 returns all public keys as base64 URL-encoded strings.
func (r *RotatingKMSSigner) AllKeysBase64() []string {
	keys := r.AllKeys()
	b64Keys := make([]string, len(keys))
	for i, key := range keys {
		b64Keys[i] = base64.RawURLEncoding.EncodeToString(key)
	}
	return b64Keys
}

// RemoveOldestKey removes the oldest previous key from the rotation.
// Returns an error if there are no previous keys to remove.
func (r *RotatingKMSSigner) RemoveOldestKey() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.previous) == 0 {
		return errors.New("no previous keys to remove")
	}

	r.previous = r.previous[:len(r.previous)-1]
	return nil
}

// ClearPreviousKeys removes all previous keys.
func (r *RotatingKMSSigner) ClearPreviousKeys() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.previous = nil
}

// RemoveKey removes a specific key by its public key from the previous keys list.
// Returns an error if the key is the current key or if it's not found.
func (r *RotatingKMSSigner) RemoveKey(publicKey []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if bytes.Equal(r.current.publicKey, publicKey) {
		return errors.New("cannot remove the current key")
	}

	for i, kv := range r.previous {
		if bytes.Equal(kv.publicKey, publicKey) {
			r.previous = append(r.previous[:i], r.previous[i+1:]...)
			return nil
		}
	}
	return errors.New("key not found")
}

// RemoveKeyBase64 removes a specific key by its base64-encoded public key.
func (r *RotatingKMSSigner) RemoveKeyBase64(publicKeyB64 string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return fmt.Errorf("decoding public key: %w", err)
	}
	return r.RemoveKey(decoded)
}

// KeyCount returns the total number of keys (current + previous).
func (r *RotatingKMSSigner) KeyCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return 1 + len(r.previous)
}

// IsCurrentKey checks if the given public key matches the current key.
func (r *RotatingKMSSigner) IsCurrentKey(publicKey []byte) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return bytes.Equal(r.current.publicKey, publicKey)
}

// IsCurrentKeyBase64 checks if the given base64-encoded public key matches the current key.
func (r *RotatingKMSSigner) IsCurrentKeyBase64(publicKeyB64 string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return false
	}
	return r.IsCurrentKey(decoded)
}

// IsKnownKey checks if the given public key matches any known key (current or previous).
func (r *RotatingKMSSigner) IsKnownKey(publicKey []byte) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if bytes.Equal(r.current.publicKey, publicKey) {
		return true
	}
	for _, kv := range r.previous {
		if bytes.Equal(kv.publicKey, publicKey) {
			return true
		}
	}
	return false
}

// IsKnownKeyBase64 checks if the given base64-encoded public key matches any known key.
func (r *RotatingKMSSigner) IsKnownKeyBase64(publicKeyB64 string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return false
	}
	return r.IsKnownKey(decoded)
}

// signWithKey signs data using a specific key version.
func (r *RotatingKMSSigner) signWithKey(ctx context.Context, keyName string, data []byte) ([]byte, error) {
	resp, err := r.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: keyName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: data,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("signing with KMS: %w", err)
	}

	return kmsDerToP1363(resp.Signature)
}

// SignWithKey signs data using the key that matches the given public key.
// This is useful for sending notifications to subscriptions created with a specific key.
func (r *RotatingKMSSigner) SignWithKey(ctx context.Context, publicKey []byte, data []byte) ([]byte, error) {
	r.mu.RLock()
	var keyName string
	if bytes.Equal(r.current.publicKey, publicKey) {
		keyName = r.current.keyName
	} else {
		for _, kv := range r.previous {
			if bytes.Equal(kv.publicKey, publicKey) {
				keyName = kv.keyName
				break
			}
		}
	}
	r.mu.RUnlock()

	if keyName == "" {
		return nil, errors.New("key not found")
	}

	return r.signWithKey(ctx, keyName, data)
}

// SignWithKeyBase64 signs data using the key that matches the given base64-encoded public key.
func (r *RotatingKMSSigner) SignWithKeyBase64(ctx context.Context, publicKeyB64 string, data []byte) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decoding public key: %w", err)
	}
	return r.SignWithKey(ctx, decoded, data)
}

// GetSignerForKey returns a Signer that uses the key matching the given public key.
// This allows creating a webpush.Client for sending to subscriptions with a specific key.
// Returns nil if the key is not found.
func (r *RotatingKMSSigner) GetSignerForKey(publicKey []byte) Signer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if bytes.Equal(r.current.publicKey, publicKey) {
		return &kmsKeyVersionSigner{
			client:  r.client,
			keyName: r.current.keyName,
			pubKey:  r.current.publicKey,
		}
	}
	for _, kv := range r.previous {
		if bytes.Equal(kv.publicKey, publicKey) {
			return &kmsKeyVersionSigner{
				client:  r.client,
				keyName: kv.keyName,
				pubKey:  kv.publicKey,
			}
		}
	}
	return nil
}

// GetSignerForKeyBase64 returns a Signer for the given base64-encoded public key.
func (r *RotatingKMSSigner) GetSignerForKeyBase64(publicKeyB64 string) Signer {
	decoded, err := base64.RawURLEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil
	}
	return r.GetSignerForKey(decoded)
}

// Close closes the underlying KMS client.
func (r *RotatingKMSSigner) Close() error {
	return r.client.Close()
}

// kmsKeyVersionSigner wraps a single KMS key version as a Signer.
type kmsKeyVersionSigner struct {
	client  *kms.KeyManagementClient
	keyName string
	pubKey  []byte
}

func (s *kmsKeyVersionSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	resp, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: s.keyName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: data,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("signing with KMS: %w", err)
	}

	return kmsDerToP1363(resp.Signature)
}

func (s *kmsKeyVersionSigner) PublicKey() []byte {
	return s.pubKey
}
