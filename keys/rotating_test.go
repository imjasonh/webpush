package keys

import (
	"context"
	"encoding/base64"
	"testing"
)

// mockSigner is a test implementation of Signer.
type mockSigner struct {
	pubKey []byte
}

func (m *mockSigner) Sign(_ context.Context, data []byte) ([]byte, error) {
	// Return a 64-byte dummy signature
	return make([]byte, 64), nil
}

func (m *mockSigner) PublicKey() []byte {
	return m.pubKey
}

func newMockSigner(id byte) *mockSigner {
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04 // Uncompressed point indicator
	pubKey[1] = id   // Unique identifier
	return &mockSigner{pubKey: pubKey}
}

func TestNewRotatingSigner(t *testing.T) {
	signer := newMockSigner(1)
	rotating := NewRotatingSigner(signer)

	if rotating.KeyCount() != 1 {
		t.Errorf("KeyCount() = %d, want 1", rotating.KeyCount())
	}

	if !rotating.IsCurrentKey(signer.PublicKey()) {
		t.Error("IsCurrentKey() returned false for current key")
	}
}

func TestRotatingSigner_Sign(t *testing.T) {
	signer := newMockSigner(1)
	rotating := NewRotatingSigner(signer)

	sig, err := rotating.Sign(context.Background(), []byte("test"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if len(sig) != 64 {
		t.Errorf("Sign() signature length = %d, want 64", len(sig))
	}
}

func TestRotatingSigner_PublicKey(t *testing.T) {
	signer := newMockSigner(1)
	rotating := NewRotatingSigner(signer)

	pubKey := rotating.PublicKey()
	if len(pubKey) != 65 {
		t.Errorf("PublicKey() length = %d, want 65", len(pubKey))
	}

	// Verify it matches the signer's key
	if !bytesEqual(pubKey, signer.PublicKey()) {
		t.Error("PublicKey() doesn't match signer's public key")
	}
}

func TestRotatingSigner_PublicKeyBase64(t *testing.T) {
	signer := newMockSigner(1)
	rotating := NewRotatingSigner(signer)

	b64Key := rotating.PublicKeyBase64()
	decoded, err := base64.RawURLEncoding.DecodeString(b64Key)
	if err != nil {
		t.Fatalf("PublicKeyBase64() returned invalid base64: %v", err)
	}

	if !bytesEqual(decoded, signer.PublicKey()) {
		t.Error("PublicKeyBase64() decoded doesn't match signer's public key")
	}
}

func TestRotatingSigner_Rotate(t *testing.T) {
	key1 := newMockSigner(1)
	key2 := newMockSigner(2)
	key3 := newMockSigner(3)

	rotating := NewRotatingSigner(key1)

	// Rotate to key2
	rotating.Rotate(key2)

	if rotating.KeyCount() != 2 {
		t.Errorf("KeyCount() after first rotation = %d, want 2", rotating.KeyCount())
	}

	if !rotating.IsCurrentKey(key2.PublicKey()) {
		t.Error("IsCurrentKey() returned false for key2 after rotation")
	}

	if rotating.IsCurrentKey(key1.PublicKey()) {
		t.Error("IsCurrentKey() returned true for key1 after rotation")
	}

	// Verify previous keys
	prevKeys := rotating.PreviousKeys()
	if len(prevKeys) != 1 {
		t.Errorf("PreviousKeys() count = %d, want 1", len(prevKeys))
	}
	if !bytesEqual(prevKeys[0], key1.PublicKey()) {
		t.Error("First previous key doesn't match key1")
	}

	// Rotate to key3
	rotating.Rotate(key3)

	if rotating.KeyCount() != 3 {
		t.Errorf("KeyCount() after second rotation = %d, want 3", rotating.KeyCount())
	}

	if !rotating.IsCurrentKey(key3.PublicKey()) {
		t.Error("IsCurrentKey() returned false for key3 after rotation")
	}

	// Verify previous keys order (most recent first)
	prevKeys = rotating.PreviousKeys()
	if len(prevKeys) != 2 {
		t.Errorf("PreviousKeys() count = %d, want 2", len(prevKeys))
	}
	if !bytesEqual(prevKeys[0], key2.PublicKey()) {
		t.Error("First previous key doesn't match key2")
	}
	if !bytesEqual(prevKeys[1], key1.PublicKey()) {
		t.Error("Second previous key doesn't match key1")
	}
}

func TestRotatingSigner_AllKeys(t *testing.T) {
	key1 := newMockSigner(1)
	key2 := newMockSigner(2)
	key3 := newMockSigner(3)

	rotating := NewRotatingSigner(key1)
	rotating.Rotate(key2)
	rotating.Rotate(key3)

	allKeys := rotating.AllKeys()
	if len(allKeys) != 3 {
		t.Fatalf("AllKeys() count = %d, want 3", len(allKeys))
	}

	// Current key first
	if !bytesEqual(allKeys[0], key3.PublicKey()) {
		t.Error("First key should be key3 (current)")
	}
	if !bytesEqual(allKeys[1], key2.PublicKey()) {
		t.Error("Second key should be key2")
	}
	if !bytesEqual(allKeys[2], key1.PublicKey()) {
		t.Error("Third key should be key1")
	}
}

func TestRotatingSigner_AllKeysBase64(t *testing.T) {
	key1 := newMockSigner(1)
	key2 := newMockSigner(2)

	rotating := NewRotatingSigner(key1)
	rotating.Rotate(key2)

	b64Keys := rotating.AllKeysBase64()
	if len(b64Keys) != 2 {
		t.Fatalf("AllKeysBase64() count = %d, want 2", len(b64Keys))
	}

	// Verify all keys are valid base64
	for i, b64Key := range b64Keys {
		decoded, err := base64.RawURLEncoding.DecodeString(b64Key)
		if err != nil {
			t.Errorf("AllKeysBase64()[%d] is not valid base64: %v", i, err)
		}
		if len(decoded) != 65 {
			t.Errorf("AllKeysBase64()[%d] decoded length = %d, want 65", i, len(decoded))
		}
	}
}

func TestRotatingSigner_RemoveOldestKey(t *testing.T) {
	key1 := newMockSigner(1)
	key2 := newMockSigner(2)
	key3 := newMockSigner(3)

	rotating := NewRotatingSigner(key1)
	rotating.Rotate(key2)
	rotating.Rotate(key3)

	// Remove oldest (key1)
	err := rotating.RemoveOldestKey()
	if err != nil {
		t.Fatalf("RemoveOldestKey() error = %v", err)
	}

	if rotating.KeyCount() != 2 {
		t.Errorf("KeyCount() after removal = %d, want 2", rotating.KeyCount())
	}

	if rotating.IsKnownKey(key1.PublicKey()) {
		t.Error("key1 should no longer be known")
	}

	// Remove oldest (key2)
	err = rotating.RemoveOldestKey()
	if err != nil {
		t.Fatalf("RemoveOldestKey() error = %v", err)
	}

	if rotating.KeyCount() != 1 {
		t.Errorf("KeyCount() after second removal = %d, want 1", rotating.KeyCount())
	}

	// Try to remove when no previous keys
	err = rotating.RemoveOldestKey()
	if err == nil {
		t.Error("RemoveOldestKey() expected error when no previous keys")
	}
}

func TestRotatingSigner_ClearPreviousKeys(t *testing.T) {
	key1 := newMockSigner(1)
	key2 := newMockSigner(2)
	key3 := newMockSigner(3)

	rotating := NewRotatingSigner(key1)
	rotating.Rotate(key2)
	rotating.Rotate(key3)

	rotating.ClearPreviousKeys()

	if rotating.KeyCount() != 1 {
		t.Errorf("KeyCount() after clear = %d, want 1", rotating.KeyCount())
	}

	if !rotating.IsCurrentKey(key3.PublicKey()) {
		t.Error("Current key should still be key3")
	}

	if rotating.IsKnownKey(key1.PublicKey()) || rotating.IsKnownKey(key2.PublicKey()) {
		t.Error("Previous keys should not be known after clear")
	}
}

func TestRotatingSigner_IsKnownKey(t *testing.T) {
	key1 := newMockSigner(1)
	key2 := newMockSigner(2)
	unknown := newMockSigner(99)

	rotating := NewRotatingSigner(key1)
	rotating.Rotate(key2)

	if !rotating.IsKnownKey(key1.PublicKey()) {
		t.Error("key1 should be known")
	}

	if !rotating.IsKnownKey(key2.PublicKey()) {
		t.Error("key2 should be known")
	}

	if rotating.IsKnownKey(unknown.PublicKey()) {
		t.Error("unknown key should not be known")
	}
}

func TestRotatingSigner_IsKnownKeyBase64(t *testing.T) {
	key1 := newMockSigner(1)
	rotating := NewRotatingSigner(key1)

	b64Key := rotating.PublicKeyBase64()
	if !rotating.IsKnownKeyBase64(b64Key) {
		t.Error("IsKnownKeyBase64() returned false for current key")
	}

	if rotating.IsKnownKeyBase64("invalid-base64!!!") {
		t.Error("IsKnownKeyBase64() should return false for invalid base64")
	}

	// Unknown key
	unknown := newMockSigner(99)
	unknownB64 := base64.RawURLEncoding.EncodeToString(unknown.PublicKey())
	if rotating.IsKnownKeyBase64(unknownB64) {
		t.Error("IsKnownKeyBase64() should return false for unknown key")
	}
}

func TestRotatingSigner_GetSignerForKey(t *testing.T) {
	key1 := newMockSigner(1)
	key2 := newMockSigner(2)
	unknown := newMockSigner(99)

	rotating := NewRotatingSigner(key1)
	rotating.Rotate(key2)

	// Get signer for current key
	signer := rotating.GetSignerForKey(key2.PublicKey())
	if signer == nil {
		t.Fatal("GetSignerForKey() returned nil for current key")
	}
	if !bytesEqual(signer.PublicKey(), key2.PublicKey()) {
		t.Error("GetSignerForKey() returned wrong signer for current key")
	}

	// Get signer for previous key
	signer = rotating.GetSignerForKey(key1.PublicKey())
	if signer == nil {
		t.Fatal("GetSignerForKey() returned nil for previous key")
	}
	if !bytesEqual(signer.PublicKey(), key1.PublicKey()) {
		t.Error("GetSignerForKey() returned wrong signer for previous key")
	}

	// Get signer for unknown key
	signer = rotating.GetSignerForKey(unknown.PublicKey())
	if signer != nil {
		t.Error("GetSignerForKey() should return nil for unknown key")
	}
}

func TestRotatingSigner_GetSignerForKeyBase64(t *testing.T) {
	key1 := newMockSigner(1)
	rotating := NewRotatingSigner(key1)

	b64Key := rotating.PublicKeyBase64()
	signer := rotating.GetSignerForKeyBase64(b64Key)
	if signer == nil {
		t.Fatal("GetSignerForKeyBase64() returned nil for current key")
	}

	// Invalid base64
	signer = rotating.GetSignerForKeyBase64("invalid-base64!!!")
	if signer != nil {
		t.Error("GetSignerForKeyBase64() should return nil for invalid base64")
	}
}

func TestRotatingSigner_PreviousKeysBase64(t *testing.T) {
	key1 := newMockSigner(1)
	key2 := newMockSigner(2)

	rotating := NewRotatingSigner(key1)
	rotating.Rotate(key2)

	prevB64 := rotating.PreviousKeysBase64()
	if len(prevB64) != 1 {
		t.Fatalf("PreviousKeysBase64() count = %d, want 1", len(prevB64))
	}

	decoded, err := base64.RawURLEncoding.DecodeString(prevB64[0])
	if err != nil {
		t.Fatalf("PreviousKeysBase64()[0] is not valid base64: %v", err)
	}
	if !bytesEqual(decoded, key1.PublicKey()) {
		t.Error("PreviousKeysBase64()[0] doesn't match key1")
	}
}

func TestRotatingSigner_IsCurrentKeyBase64(t *testing.T) {
	key1 := newMockSigner(1)
	key2 := newMockSigner(2)

	rotating := NewRotatingSigner(key1)
	rotating.Rotate(key2)

	key2B64 := base64.RawURLEncoding.EncodeToString(key2.PublicKey())
	if !rotating.IsCurrentKeyBase64(key2B64) {
		t.Error("IsCurrentKeyBase64() returned false for current key")
	}

	key1B64 := base64.RawURLEncoding.EncodeToString(key1.PublicKey())
	if rotating.IsCurrentKeyBase64(key1B64) {
		t.Error("IsCurrentKeyBase64() returned true for previous key")
	}

	if rotating.IsCurrentKeyBase64("invalid-base64!!!") {
		t.Error("IsCurrentKeyBase64() should return false for invalid base64")
	}
}

// Test thread safety with concurrent operations
func TestRotatingSigner_Concurrent(t *testing.T) {
	key1 := newMockSigner(1)
	rotating := NewRotatingSigner(key1)

	done := make(chan bool)
	ctx := context.Background()

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				rotating.PublicKey()
				rotating.AllKeys()
				rotating.IsKnownKey(key1.PublicKey())
			}
			done <- true
		}()
	}

	// Concurrent writes
	for i := 0; i < 5; i++ {
		go func(id int) {
			for j := 0; j < 20; j++ {
				newKey := newMockSigner(byte(100 + id*20 + j))
				rotating.Rotate(newKey)
			}
			done <- true
		}(i)
	}

	// Concurrent signs
	for i := 0; i < 5; i++ {
		go func() {
			for j := 0; j < 50; j++ {
				rotating.Sign(ctx, []byte("test"))
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}

	// Verify the signer is still functional
	if rotating.KeyCount() < 1 {
		t.Error("KeyCount() should be at least 1")
	}

	_, err := rotating.Sign(ctx, []byte("final test"))
	if err != nil {
		t.Errorf("Sign() after concurrent operations error = %v", err)
	}
}
