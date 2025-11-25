package webpush_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/imjasonh/webpush"
	"github.com/imjasonh/webpush/keys"
	"github.com/imjasonh/webpush/storage"
)

// TestIntegration_FullFlow tests the complete flow of generating keys,
// storing subscriptions, and sending push notifications.
func TestIntegration_FullFlow(t *testing.T) {
	// 1. Generate VAPID keys
	privateKeyB64, publicKeyB64, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	t.Logf("Generated public key: %s", publicKeyB64)

	// 2. Create signer from generated key
	signer, err := keys.NewFileSignerFromBase64(privateKeyB64)
	if err != nil {
		t.Fatalf("NewFileSignerFromBase64() error = %v", err)
	}

	// Verify public keys match
	if signer.PublicKeyBase64() != publicKeyB64 {
		t.Errorf("Public keys don't match")
	}

	// 3. Create storage
	store := storage.NewMemory()

	// 4. Create a mock push service
	pushReceived := make(chan struct{}, 1)
	pushServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers
		if r.Header.Get("Authorization") == "" {
			t.Error("Missing Authorization header")
		}
		if r.Header.Get("Content-Encoding") != "aes128gcm" {
			t.Errorf("Content-Encoding = %q, want %q", r.Header.Get("Content-Encoding"), "aes128gcm")
		}
		if r.Header.Get("TTL") == "" {
			t.Error("Missing TTL header")
		}

		// Read body to verify it's encrypted
		body, _ := io.ReadAll(r.Body)
		if len(body) < 86 { // Minimum header size
			t.Errorf("Body too short: %d bytes", len(body))
		}

		pushReceived <- struct{}{}
		w.WriteHeader(http.StatusCreated)
	}))
	defer pushServer.Close()

	// 5. Simulate client subscription
	// In real world, this would come from the browser's PushManager.subscribe()
	clientSubJSON := []byte(`{
		"endpoint": "` + pushServer.URL + `/push/abc123",
		"keys": {
			"p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM",
			"auth": "tBHItJI5svbpez7KI4CCXg"
		}
	}`)

	sub, err := webpush.ParseSubscription(clientSubJSON)
	if err != nil {
		t.Fatalf("ParseSubscription() error = %v", err)
	}

	// 6. Store the subscription
	record := &storage.Record{
		ID:           "sub-1",
		UserID:       "user-123",
		Subscription: sub,
	}
	if err := store.Save(context.Background(), record); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// 7. Retrieve subscriptions for user
	records, err := store.GetByUserID(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("GetByUserID() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("GetByUserID() count = %d, want 1", len(records))
	}

	// 8. Create web push client and send notification
	client := webpush.NewClient(signer, "mailto:test@example.com")
	client.WithHTTPClient(pushServer.Client())

	payload := map[string]string{
		"title": "Hello",
		"body":  "World",
	}
	payloadJSON, _ := json.Marshal(payload)

	err = client.Send(context.Background(), records[0].Subscription, payloadJSON, &webpush.Options{
		TTL:     3600,
		Urgency: "high",
	})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	// 9. Verify push was received
	select {
	case <-pushReceived:
		t.Log("Push notification received by mock service")
	default:
		t.Error("Push notification not received")
	}
}

// TestIntegration_MultipleSubscriptions tests sending to multiple subscriptions.
func TestIntegration_MultipleSubscriptions(t *testing.T) {
	// Generate keys
	privateKeyB64, _, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	signer, err := keys.NewFileSignerFromBase64(privateKeyB64)
	if err != nil {
		t.Fatalf("NewFileSignerFromBase64() error = %v", err)
	}

	// Track received pushes
	receivedCount := 0
	pushServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCount++
		w.WriteHeader(http.StatusCreated)
	}))
	defer pushServer.Close()

	store := storage.NewMemory()
	ctx := context.Background()

	// Create multiple subscriptions for same user
	for i := 0; i < 3; i++ {
		record := &storage.Record{
			ID:     "sub-" + string(rune('a'+i)),
			UserID: "user-1",
			Subscription: &webpush.Subscription{
				Endpoint: pushServer.URL + "/push/" + string(rune('a'+i)),
				Keys: webpush.Keys{
					P256dh: "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM",
					Auth:   "tBHItJI5svbpez7KI4CCXg",
				},
			},
		}
		if err := store.Save(ctx, record); err != nil {
			t.Fatalf("Save() error = %v", err)
		}
	}

	// Send to all user's subscriptions
	client := webpush.NewClient(signer, "mailto:test@example.com")
	client.WithHTTPClient(pushServer.Client())

	records, err := store.GetByUserID(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetByUserID() error = %v", err)
	}

	for _, record := range records {
		err := client.Send(ctx, record.Subscription, []byte(`{"test":true}`), nil)
		if err != nil {
			t.Errorf("Send() error = %v", err)
		}
	}

	if receivedCount != 3 {
		t.Errorf("Received %d pushes, want 3", receivedCount)
	}
}

// TestIntegration_SQLiteStorage tests the SQLite storage backend.
func TestIntegration_SQLiteStorage(t *testing.T) {
	store, err := storage.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite() error = %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Save multiple subscriptions
	for i := 0; i < 5; i++ {
		record := &storage.Record{
			ID:     "sub-" + string(rune('a'+i)),
			UserID: "user-1",
			Subscription: &webpush.Subscription{
				Endpoint: "https://push.example.com/" + string(rune('a'+i)),
				Keys: webpush.Keys{
					P256dh: "key-" + string(rune('a'+i)),
					Auth:   "auth-" + string(rune('a'+i)),
				},
			},
		}
		if err := store.Save(ctx, record); err != nil {
			t.Fatalf("Save() error = %v", err)
		}
	}

	// List with pagination
	page1, err := store.List(ctx, 2, 0)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page1) != 2 {
		t.Errorf("Page 1 len = %d, want 2", len(page1))
	}

	page2, err := store.List(ctx, 2, 2)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page2) != 2 {
		t.Errorf("Page 2 len = %d, want 2", len(page2))
	}

	page3, err := store.List(ctx, 2, 4)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page3) != 1 {
		t.Errorf("Page 3 len = %d, want 1", len(page3))
	}
}
