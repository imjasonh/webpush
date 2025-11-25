package webpush

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockSigner is a test implementation of Signer.
type mockSigner struct {
	pubKey []byte
}

func (m *mockSigner) Sign(_ context.Context, _ []byte) ([]byte, error) {
	// Return a 64-byte dummy signature
	return make([]byte, 64), nil
}

func (m *mockSigner) PublicKey() []byte {
	return m.pubKey
}

func TestParseSubscription(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{
			name: "valid subscription",
			json: `{
				"endpoint": "https://push.example.com/abc123",
				"keys": {
					"p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM",
					"auth": "tBHItJI5svbpez7KI4CCXg"
				}
			}`,
			wantErr: false,
		},
		{
			name:    "empty JSON",
			json:    `{}`,
			wantErr: true,
		},
		{
			name: "missing endpoint",
			json: `{
				"keys": {
					"p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM",
					"auth": "tBHItJI5svbpez7KI4CCXg"
				}
			}`,
			wantErr: true,
		},
		{
			name: "missing p256dh",
			json: `{
				"endpoint": "https://push.example.com/abc123",
				"keys": {
					"auth": "tBHItJI5svbpez7KI4CCXg"
				}
			}`,
			wantErr: true,
		},
		{
			name: "missing auth",
			json: `{
				"endpoint": "https://push.example.com/abc123",
				"keys": {
					"p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM"
				}
			}`,
			wantErr: true,
		},
		{
			name: "non-https endpoint",
			json: `{
				"endpoint": "http://push.example.com/abc123",
				"keys": {
					"p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM",
					"auth": "tBHItJI5svbpez7KI4CCXg"
				}
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSubscription([]byte(tt.json))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSubscription() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_Send(t *testing.T) {
	// Create a test server to simulate push service
	receivedRequests := make(chan *http.Request, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Store request for verification
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		receivedRequests <- r
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	// Generate test keys for a valid P-256 public key
	p256dhBytes, _ := base64.RawURLEncoding.DecodeString("BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM")
	authBytes := make([]byte, 16)

	// Create subscription pointing to our test server
	sub := &Subscription{
		Endpoint: server.URL + "/push/abc123",
		Keys: Keys{
			P256dh: base64.RawURLEncoding.EncodeToString(p256dhBytes),
			Auth:   base64.RawURLEncoding.EncodeToString(authBytes),
		},
	}

	// Create a mock signer with a valid P-256 public key
	signer := &mockSigner{
		pubKey: p256dhBytes, // Use same key format for simplicity
	}

	client := NewClient(signer, "mailto:test@example.com")
	client.WithHTTPClient(server.Client())

	// Send notification
	err := client.Send(context.Background(), sub, []byte("test message"), nil)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	// Verify request was received
	select {
	case req := <-receivedRequests:
		if req.Header.Get("Content-Encoding") != "aes128gcm" {
			t.Errorf("Content-Encoding = %q, want %q", req.Header.Get("Content-Encoding"), "aes128gcm")
		}
		if req.Header.Get("TTL") == "" {
			t.Error("TTL header not set")
		}
		if req.Header.Get("Authorization") == "" {
			t.Error("Authorization header not set")
		}
	default:
		t.Error("No request received")
	}
}

func TestClient_SendWithOptions(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify options headers
		if r.Header.Get("Urgency") != "high" {
			t.Errorf("Urgency = %q, want %q", r.Header.Get("Urgency"), "high")
		}
		if r.Header.Get("Topic") != "test-topic" {
			t.Errorf("Topic = %q, want %q", r.Header.Get("Topic"), "test-topic")
		}
		if r.Header.Get("TTL") != "3600" {
			t.Errorf("TTL = %q, want %q", r.Header.Get("TTL"), "3600")
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	p256dhBytes, _ := base64.RawURLEncoding.DecodeString("BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM")
	authBytes := make([]byte, 16)

	sub := &Subscription{
		Endpoint: server.URL + "/push/abc123",
		Keys: Keys{
			P256dh: base64.RawURLEncoding.EncodeToString(p256dhBytes),
			Auth:   base64.RawURLEncoding.EncodeToString(authBytes),
		},
	}

	signer := &mockSigner{pubKey: p256dhBytes}
	client := NewClient(signer, "mailto:test@example.com")
	client.WithHTTPClient(server.Client())

	err := client.Send(context.Background(), sub, []byte("test"), &Options{
		TTL:     3600,
		Urgency: "high",
		Topic:   "test-topic",
	})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}

func TestClient_SendError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
		w.Write([]byte("subscription has expired"))
	}))
	defer server.Close()

	p256dhBytes, _ := base64.RawURLEncoding.DecodeString("BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM")
	authBytes := make([]byte, 16)

	sub := &Subscription{
		Endpoint: server.URL + "/push/abc123",
		Keys: Keys{
			P256dh: base64.RawURLEncoding.EncodeToString(p256dhBytes),
			Auth:   base64.RawURLEncoding.EncodeToString(authBytes),
		},
	}

	signer := &mockSigner{pubKey: p256dhBytes}
	client := NewClient(signer, "mailto:test@example.com")
	client.WithHTTPClient(server.Client())

	err := client.Send(context.Background(), sub, []byte("test"), nil)
	if err == nil {
		t.Fatal("Send() expected error, got nil")
	}
}

func TestSubscription_JSON(t *testing.T) {
	sub := &Subscription{
		Endpoint: "https://push.example.com/abc123",
		Keys: Keys{
			P256dh: "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM",
			Auth:   "tBHItJI5svbpez7KI4CCXg",
		},
	}

	data, err := json.Marshal(sub)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded Subscription
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if decoded.Endpoint != sub.Endpoint {
		t.Errorf("Endpoint = %q, want %q", decoded.Endpoint, sub.Endpoint)
	}
	if decoded.Keys.P256dh != sub.Keys.P256dh {
		t.Errorf("P256dh = %q, want %q", decoded.Keys.P256dh, sub.Keys.P256dh)
	}
	if decoded.Keys.Auth != sub.Keys.Auth {
		t.Errorf("Auth = %q, want %q", decoded.Keys.Auth, sub.Keys.Auth)
	}
}
