package vapid

import (
	"encoding/base64"
	"testing"
)

func TestApplicationServerKey(t *testing.T) {
	// Test with a sample 65-byte P-256 public key
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04 // Uncompressed point indicator

	result := ApplicationServerKey(pubKey)

	// Verify it's valid base64
	decoded, err := base64.RawURLEncoding.DecodeString(result)
	if err != nil {
		t.Fatalf("ApplicationServerKey() returned invalid base64: %v", err)
	}

	if len(decoded) != 65 {
		t.Errorf("Decoded length = %d, want 65", len(decoded))
	}

	if decoded[0] != 0x04 {
		t.Errorf("First byte = %d, want 4", decoded[0])
	}
}

func TestDecodeApplicationServerKey(t *testing.T) {
	// Create a known key
	original := make([]byte, 65)
	original[0] = 0x04
	for i := 1; i < 65; i++ {
		original[i] = byte(i)
	}

	// Encode it
	encoded := ApplicationServerKey(original)

	// Decode it back
	decoded, err := DecodeApplicationServerKey(encoded)
	if err != nil {
		t.Fatalf("DecodeApplicationServerKey() error = %v", err)
	}

	if len(decoded) != len(original) {
		t.Fatalf("Decoded length = %d, want %d", len(decoded), len(original))
	}

	for i := range original {
		if decoded[i] != original[i] {
			t.Errorf("Decoded[%d] = %d, want %d", i, decoded[i], original[i])
		}
	}
}

func TestDecodeApplicationServerKey_Invalid(t *testing.T) {
	_, err := DecodeApplicationServerKey("not-valid-base64!!!")
	if err == nil {
		t.Error("DecodeApplicationServerKey() expected error for invalid input")
	}
}
