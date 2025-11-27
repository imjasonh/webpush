// Package keys provides VAPID key implementations.
package keys

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
)

// Signer provides VAPID signing functionality.
// This mirrors the webpush.Signer interface to avoid import cycles.
type Signer interface {
	// Sign signs the given data and returns the signature.
	Sign(ctx context.Context, data []byte) ([]byte, error)
	// PublicKey returns the ECDSA public key in uncompressed format.
	PublicKey() []byte
}

// RotatingSigner implements key rotation by managing multiple keys.
// It holds a current (primary) key for signing new operations and
// optionally previous keys that may still be needed for existing subscriptions.
//
// When a VAPID key is rotated, existing browser subscriptions are invalidated
// because they are tied to the applicationServerKey (VAPID public key).
// The RotatingSigner helps manage this transition by:
//  1. Signing all new operations with the current key
//  2. Tracking previous keys so you can identify which subscriptions need re-subscription
//  3. Providing all public keys to help migrate subscriptions
type RotatingSigner struct {
	mu       sync.RWMutex
	current  Signer
	previous []Signer
}

// NewRotatingSigner creates a new rotating signer with the given current key.
func NewRotatingSigner(current Signer) *RotatingSigner {
	return &RotatingSigner{
		current:  current,
		previous: nil,
	}
}

// Sign signs the given data using the current key.
func (r *RotatingSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current.Sign(ctx, data)
}

// PublicKey returns the current ECDSA public key in uncompressed format.
func (r *RotatingSigner) PublicKey() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current.PublicKey()
}

// PublicKeyBase64 returns the current public key as a base64 URL-encoded string.
func (r *RotatingSigner) PublicKeyBase64() string {
	return base64.RawURLEncoding.EncodeToString(r.PublicKey())
}

// Rotate adds a new key as the current key and moves the old current key
// to the previous keys list. The new key will be used for all new signing
// operations.
//
// After rotation, existing subscriptions created with the old key will
// need to be re-subscribed by clients using the new applicationServerKey.
func (r *RotatingSigner) Rotate(newKey Signer) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Move current to previous
	r.previous = append([]Signer{r.current}, r.previous...)
	r.current = newKey
}

// PreviousKeys returns all previous public keys in order from most recent to oldest.
func (r *RotatingSigner) PreviousKeys() [][]byte {
	r.mu.RLock()
	defer r.mu.RUnlock()

	keys := make([][]byte, len(r.previous))
	for i, signer := range r.previous {
		keys[i] = signer.PublicKey()
	}
	return keys
}

// PreviousKeysBase64 returns all previous public keys as base64 URL-encoded strings.
func (r *RotatingSigner) PreviousKeysBase64() []string {
	keys := r.PreviousKeys()
	b64Keys := make([]string, len(keys))
	for i, key := range keys {
		b64Keys[i] = base64.RawURLEncoding.EncodeToString(key)
	}
	return b64Keys
}

// AllKeys returns all public keys (current and previous) with current first.
func (r *RotatingSigner) AllKeys() [][]byte {
	r.mu.RLock()
	defer r.mu.RUnlock()

	keys := make([][]byte, 1+len(r.previous))
	keys[0] = r.current.PublicKey()
	for i, signer := range r.previous {
		keys[i+1] = signer.PublicKey()
	}
	return keys
}

// AllKeysBase64 returns all public keys as base64 URL-encoded strings.
func (r *RotatingSigner) AllKeysBase64() []string {
	keys := r.AllKeys()
	b64Keys := make([]string, len(keys))
	for i, key := range keys {
		b64Keys[i] = base64.RawURLEncoding.EncodeToString(key)
	}
	return b64Keys
}

// RemoveOldestKey removes the oldest previous key from the rotation.
// Returns an error if there are no previous keys to remove.
func (r *RotatingSigner) RemoveOldestKey() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.previous) == 0 {
		return errors.New("no previous keys to remove")
	}

	r.previous = r.previous[:len(r.previous)-1]
	return nil
}

// ClearPreviousKeys removes all previous keys.
func (r *RotatingSigner) ClearPreviousKeys() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.previous = nil
}

// RemoveKey removes a specific key by its public key from the previous keys list.
// Returns an error if the key is the current key or if it's not found.
func (r *RotatingSigner) RemoveKey(publicKey []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if bytes.Equal(r.current.PublicKey(), publicKey) {
		return errors.New("cannot remove the current key")
	}

	for i, signer := range r.previous {
		if bytes.Equal(signer.PublicKey(), publicKey) {
			r.previous = append(r.previous[:i], r.previous[i+1:]...)
			return nil
		}
	}
	return errors.New("key not found")
}

// RemoveKeyBase64 removes a specific key by its base64-encoded public key.
func (r *RotatingSigner) RemoveKeyBase64(publicKeyB64 string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return fmt.Errorf("decoding public key: %w", err)
	}
	return r.RemoveKey(decoded)
}

// KeyCount returns the total number of keys (current + previous).
func (r *RotatingSigner) KeyCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return 1 + len(r.previous)
}

// IsCurrentKey checks if the given public key matches the current key.
func (r *RotatingSigner) IsCurrentKey(publicKey []byte) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return bytes.Equal(r.current.PublicKey(), publicKey)
}

// IsCurrentKeyBase64 checks if the given base64-encoded public key matches the current key.
func (r *RotatingSigner) IsCurrentKeyBase64(publicKeyB64 string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return false
	}
	return r.IsCurrentKey(decoded)
}

// IsKnownKey checks if the given public key matches any known key (current or previous).
func (r *RotatingSigner) IsKnownKey(publicKey []byte) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if bytes.Equal(r.current.PublicKey(), publicKey) {
		return true
	}
	for _, signer := range r.previous {
		if bytes.Equal(signer.PublicKey(), publicKey) {
			return true
		}
	}
	return false
}

// IsKnownKeyBase64 checks if the given base64-encoded public key matches any known key.
func (r *RotatingSigner) IsKnownKeyBase64(publicKeyB64 string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return false
	}
	return r.IsKnownKey(decoded)
}

// GetSignerForKey returns the signer for the given public key, or nil if not found.
// This can be used to send notifications using a specific key for subscriptions
// that were created with that key.
func (r *RotatingSigner) GetSignerForKey(publicKey []byte) Signer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if bytes.Equal(r.current.PublicKey(), publicKey) {
		return r.current
	}
	for _, signer := range r.previous {
		if bytes.Equal(signer.PublicKey(), publicKey) {
			return signer
		}
	}
	return nil
}

// GetSignerForKeyBase64 returns the signer for the given base64-encoded public key.
func (r *RotatingSigner) GetSignerForKeyBase64(publicKeyB64 string) Signer {
	decoded, err := base64.RawURLEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil
	}
	return r.GetSignerForKey(decoded)
}
