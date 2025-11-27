package keys

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
)

// mockCounter implements SubscriptionCounter for testing.
type mockCounter struct {
	counts map[string]int
}

func newMockCounter() *mockCounter {
	return &mockCounter{
		counts: make(map[string]int),
	}
}

func (m *mockCounter) CountByVAPIDKey(_ context.Context, vapidKey string) (int, error) {
	return m.counts[vapidKey], nil
}

func (m *mockCounter) setCount(pubKey []byte, count int) {
	b64 := base64.RawURLEncoding.EncodeToString(pubKey)
	m.counts[b64] = count
}

func TestRotatingSigner_RemoveKey(t *testing.T) {
	key1 := newMockSigner(1)
	key2 := newMockSigner(2)
	key3 := newMockSigner(3)

	rotating := NewRotatingSigner(key1)
	rotating.Rotate(key2)
	rotating.Rotate(key3)

	// Try to remove current key - should fail
	err := rotating.RemoveKey(key3.PublicKey())
	if err == nil {
		t.Error("RemoveKey() should fail for current key")
	}

	// Remove a previous key
	err = rotating.RemoveKey(key1.PublicKey())
	if err != nil {
		t.Fatalf("RemoveKey() error = %v", err)
	}

	if rotating.KeyCount() != 2 {
		t.Errorf("KeyCount() = %d, want 2", rotating.KeyCount())
	}

	if rotating.IsKnownKey(key1.PublicKey()) {
		t.Error("key1 should no longer be known")
	}

	// Try to remove unknown key - should fail
	unknown := newMockSigner(99)
	err = rotating.RemoveKey(unknown.PublicKey())
	if err == nil {
		t.Error("RemoveKey() should fail for unknown key")
	}
}

func TestRotatingSigner_RemoveKeyBase64(t *testing.T) {
	key1 := newMockSigner(1)
	key2 := newMockSigner(2)

	rotating := NewRotatingSigner(key1)
	rotating.Rotate(key2)

	key1B64 := base64.RawURLEncoding.EncodeToString(key1.PublicKey())
	err := rotating.RemoveKeyBase64(key1B64)
	if err != nil {
		t.Fatalf("RemoveKeyBase64() error = %v", err)
	}

	if rotating.IsKnownKey(key1.PublicKey()) {
		t.Error("key1 should no longer be known")
	}

	// Invalid base64
	err = rotating.RemoveKeyBase64("invalid-base64!!!")
	if err == nil {
		t.Error("RemoveKeyBase64() should fail for invalid base64")
	}
}

func TestRotatingSigner_RemoveUnusedKeys(t *testing.T) {
	key1 := newMockSigner(1)
	key2 := newMockSigner(2)
	key3 := newMockSigner(3)

	rotating := NewRotatingSigner(key1)
	rotating.Rotate(key2)
	rotating.Rotate(key3)

	counter := newMockCounter()
	// key1 has no subscriptions
	counter.setCount(key1.PublicKey(), 0)
	// key2 has 5 subscriptions
	counter.setCount(key2.PublicKey(), 5)

	ctx := context.Background()
	result, err := rotating.RemoveUnusedKeys(ctx, counter)
	if err != nil {
		t.Fatalf("RemoveUnusedKeys() error = %v", err)
	}

	// key1 should be removed
	if len(result.RemovedKeys) != 1 {
		t.Errorf("RemovedKeys count = %d, want 1", len(result.RemovedKeys))
	}
	key1B64 := base64.RawURLEncoding.EncodeToString(key1.PublicKey())
	if len(result.RemovedKeys) > 0 && result.RemovedKeys[0] != key1B64 {
		t.Errorf("RemovedKeys[0] = %s, want %s", result.RemovedKeys[0], key1B64)
	}

	// key2 should be retained
	if len(result.RetainedKeys) != 1 {
		t.Errorf("RetainedKeys count = %d, want 1", len(result.RetainedKeys))
	}

	// Verify state
	if rotating.KeyCount() != 2 {
		t.Errorf("KeyCount() = %d, want 2 (current + key2)", rotating.KeyCount())
	}

	if rotating.IsKnownKey(key1.PublicKey()) {
		t.Error("key1 should no longer be known")
	}

	if !rotating.IsKnownKey(key2.PublicKey()) {
		t.Error("key2 should still be known")
	}

	// Current key should still be key3
	if !rotating.IsCurrentKey(key3.PublicKey()) {
		t.Error("Current key should still be key3")
	}
}

func TestRotatingSigner_RemoveUnusedKeys_AllUnused(t *testing.T) {
	key1 := newMockSigner(1)
	key2 := newMockSigner(2)
	key3 := newMockSigner(3)

	rotating := NewRotatingSigner(key1)
	rotating.Rotate(key2)
	rotating.Rotate(key3)

	counter := newMockCounter()
	// All previous keys have no subscriptions
	counter.setCount(key1.PublicKey(), 0)
	counter.setCount(key2.PublicKey(), 0)

	ctx := context.Background()
	result, err := rotating.RemoveUnusedKeys(ctx, counter)
	if err != nil {
		t.Fatalf("RemoveUnusedKeys() error = %v", err)
	}

	if len(result.RemovedKeys) != 2 {
		t.Errorf("RemovedKeys count = %d, want 2", len(result.RemovedKeys))
	}

	if len(result.RetainedKeys) != 0 {
		t.Errorf("RetainedKeys count = %d, want 0", len(result.RetainedKeys))
	}

	// Only current key should remain
	if rotating.KeyCount() != 1 {
		t.Errorf("KeyCount() = %d, want 1", rotating.KeyCount())
	}
}

func TestRotatingSigner_RemoveUnusedKeys_AllUsed(t *testing.T) {
	key1 := newMockSigner(1)
	key2 := newMockSigner(2)
	key3 := newMockSigner(3)

	rotating := NewRotatingSigner(key1)
	rotating.Rotate(key2)
	rotating.Rotate(key3)

	counter := newMockCounter()
	// All previous keys have subscriptions
	counter.setCount(key1.PublicKey(), 10)
	counter.setCount(key2.PublicKey(), 5)

	ctx := context.Background()
	result, err := rotating.RemoveUnusedKeys(ctx, counter)
	if err != nil {
		t.Fatalf("RemoveUnusedKeys() error = %v", err)
	}

	if len(result.RemovedKeys) != 0 {
		t.Errorf("RemovedKeys count = %d, want 0", len(result.RemovedKeys))
	}

	if len(result.RetainedKeys) != 2 {
		t.Errorf("RetainedKeys count = %d, want 2", len(result.RetainedKeys))
	}

	// All keys should remain
	if rotating.KeyCount() != 3 {
		t.Errorf("KeyCount() = %d, want 3", rotating.KeyCount())
	}
}

func TestRotatingSigner_RemoveUnusedKeys_NoPrevious(t *testing.T) {
	key1 := newMockSigner(1)
	rotating := NewRotatingSigner(key1)

	counter := newMockCounter()

	ctx := context.Background()
	result, err := rotating.RemoveUnusedKeys(ctx, counter)
	if err != nil {
		t.Fatalf("RemoveUnusedKeys() error = %v", err)
	}

	if len(result.RemovedKeys) != 0 {
		t.Errorf("RemovedKeys count = %d, want 0", len(result.RemovedKeys))
	}

	if len(result.RetainedKeys) != 0 {
		t.Errorf("RetainedKeys count = %d, want 0", len(result.RetainedKeys))
	}

	if rotating.KeyCount() != 1 {
		t.Errorf("KeyCount() = %d, want 1", rotating.KeyCount())
	}
}

// Test that RemoveKey preserves order of remaining keys
func TestRotatingSigner_RemoveKey_PreservesOrder(t *testing.T) {
	key1 := newMockSigner(1)
	key2 := newMockSigner(2)
	key3 := newMockSigner(3)
	key4 := newMockSigner(4)

	rotating := NewRotatingSigner(key1)
	rotating.Rotate(key2)
	rotating.Rotate(key3)
	rotating.Rotate(key4)

	// Remove middle key (key2)
	err := rotating.RemoveKey(key2.PublicKey())
	if err != nil {
		t.Fatalf("RemoveKey() error = %v", err)
	}

	// Check previous keys order
	prevKeys := rotating.PreviousKeys()
	if len(prevKeys) != 2 {
		t.Fatalf("PreviousKeys() count = %d, want 2", len(prevKeys))
	}

	// key3 should be first (most recent), key1 should be second
	if !bytes.Equal(prevKeys[0], key3.PublicKey()) {
		t.Error("First previous key should be key3")
	}
	if !bytes.Equal(prevKeys[1], key1.PublicKey()) {
		t.Error("Second previous key should be key1")
	}
}
