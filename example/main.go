// Package main demonstrates a web push notification server.
//
// This example:
// - Sets up VAPID keys on disk (generates if not present)
// - Uses SQLite for subscription storage
// - Serves a web client for subscribing to notifications
// - Sends push notifications every minute
// - Sends push notifications on /ping requests
package main

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chainguard-dev/clog"
	_ "github.com/chainguard-dev/clog/gcp/init"
	"github.com/google/uuid"
	"github.com/imjasonh/webpush"
	"github.com/imjasonh/webpush/keys"
	"github.com/imjasonh/webpush/storage"
	"github.com/sethvargo/go-envconfig"
)

//go:embed static/*
var staticFiles embed.FS

const (
	keyPath   = "/tmp/vapid-private.pem"
	dbPath    = "/tmp/subscriptions.db"
	subject   = "mailto:admin@example.com"
	serverURL = "http://localhost:8080"
)

var (
	store  storage.Storage
	client *webpush.Client
	signer webpush.Signer
)

var env = envconfig.MustProcess(context.Background(), &struct {
	KMSKeyName string `env:"KMS_KEY_NAME" default:""`
}{})

func main() {
	ctx := context.Background()
	var err error

	// Initialize or load VAPID keys
	if env.KMSKeyName != "" {
		clog.Infof("Using KMS for VAPID keys: %s", env.KMSKeyName)
		signer, err = keys.NewKMSSigner(ctx, env.KMSKeyName)
		if err != nil {
			clog.Fatalf("Failed to initialize KMS signer: %v", err)
		}
	} else if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		clog.Info("Generating new VAPID keys...")
		signer, err = keys.GenerateKey(keyPath)
		if err != nil {
			clog.Fatalf("Failed to generate keys: %v", err)
		}
		clog.Info("VAPID keys generated and saved to", keyPath)
	} else {
		signer, err = keys.NewFileSigner(keyPath)
		if err != nil {
			clog.Fatalf("Failed to load keys: %v", err)
		}
		clog.Info("VAPID keys loaded from", keyPath)
	}

	// Initialize SQLite storage
	store, err = storage.NewSQLite(dbPath)
	if err != nil {
		clog.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()
	clog.Info("SQLite storage initialized at", dbPath)

	// Create web push client
	client = webpush.NewClient(signer, subject)

	// Start periodic push sender
	go periodicPush()

	// Set up HTTP handlers
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		clog.Fatalf("Failed to create static file system: %v", err)
	}
	http.Handle("/", http.FileServer(http.FS(staticFS)))
	http.HandleFunc("/api/vapid-public-key", handleVAPIDPublicKey)
	http.HandleFunc("/api/subscribe", handleSubscribe)
	http.HandleFunc("/api/unsubscribe", handleUnsubscribe)
	http.HandleFunc("/ping", handlePing)

	clog.Infof("Server starting at %s", serverURL)
	clog.Infof("Visit %s to subscribe to push notifications", serverURL)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		clog.Fatalf("Server failed: %v", err)
	}
}

// periodicPush sends a push notification to all subscribers every minute.
func periodicPush() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sendToAll("Periodic Update", "This notification is sent every minute!")
	}
}

// sendToAll sends a push notification to all subscribers.
func sendToAll(title, body string) {
	ctx := context.Background()

	records, err := store.List(ctx, 1000, 0)
	if err != nil {
		clog.Infof("Failed to list subscriptions: %v", err)
		return
	}

	if len(records) == 0 {
		clog.Info("No subscribers to notify")
		return
	}

	payload, err := json.Marshal(map[string]string{
		"title": title,
		"body":  body,
	})
	if err != nil {
		clog.Infof("Failed to marshal payload: %v", err)
		return
	}

	var sent, failed int
	for _, record := range records {
		err := client.Send(ctx, record.Subscription, payload, &webpush.Options{
			TTL:     3600,
			Urgency: "normal",
		})
		if err != nil {
			clog.Infof("Failed to send to %s: %v", record.ID, err)
			failed++
			// Clean up expired/invalid subscriptions (410 Gone)
			if isGone(err) {
				if delErr := store.Delete(ctx, record.ID); delErr != nil {
					clog.Infof("Failed to delete expired subscription: %v", delErr)
				} else {
					clog.Infof("Deleted expired subscription: %s", record.ID)
				}
			}
		} else {
			sent++
		}
	}

	clog.Infof("Push sent: %d successful, %d failed", sent, failed)
}

func isGone(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "410") || strings.Contains(err.Error(), "Gone"))
}

// HTTP Handlers

func handleVAPIDPublicKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	publicKeyB64 := base64.RawURLEncoding.EncodeToString(signer.PublicKey())
	json.NewEncoder(w).Encode(map[string]string{
		"publicKey": publicKeyB64,
		// Include a truncated key ID that clients can use to detect key rotation
		// When this changes, clients know they need to resubscribe
		"keyId": publicKeyB64[:16],
	})
}

func handleSubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var sub webpush.Subscription
	if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if sub.Endpoint == "" || sub.Keys.P256dh == "" || sub.Keys.Auth == "" {
		http.Error(w, "Invalid subscription", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Check if already subscribed
	existing, err := store.GetByEndpoint(ctx, sub.Endpoint)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"id":      existing.ID,
			"message": "Already subscribed",
		})
		return
	}

	// Save new subscription
	record := &storage.Record{
		ID:           uuid.New().String(),
		Subscription: &sub,
	}

	if err := store.Save(ctx, record); err != nil {
		http.Error(w, "Failed to save subscription: "+err.Error(), http.StatusInternalServerError)
		return
	}

	clog.Infof("New subscription: %s", record.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":      record.ID,
		"message": "Subscribed successfully",
	})
}

func handleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Endpoint string `json:"endpoint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := store.DeleteByEndpoint(r.Context(), req.Endpoint); err != nil {
		http.Error(w, "Subscription not found", http.StatusNotFound)
		return
	}

	clog.Infof("Unsubscribed: %s", req.Endpoint)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Unsubscribed successfully",
	})
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	title := r.URL.Query().Get("title")
	if title == "" {
		title = "Ping!"
	}
	body := r.URL.Query().Get("body")
	if body == "" {
		body = "Someone pinged the server at " + time.Now().Format(time.RFC3339)
	}

	go sendToAll(title, body)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Push notification queued",
	})
}
