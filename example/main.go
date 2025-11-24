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
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/imjasonh/webpush"
	"github.com/imjasonh/webpush/keys"
	"github.com/imjasonh/webpush/storage"
)

//go:embed static/*
var staticFiles embed.FS

const (
	keyPath   = "vapid-private.pem"
	dbPath    = "subscriptions.db"
	subject   = "mailto:admin@example.com"
	serverURL = "http://localhost:8080"
)

var (
	store  storage.Storage
	client *webpush.Client
	signer *keys.FileSigner
	mu     sync.RWMutex
)

func main() {
	var err error

	// Initialize or load VAPID keys
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		log.Println("Generating new VAPID keys...")
		signer, err = keys.GenerateKey(keyPath)
		if err != nil {
			log.Fatalf("Failed to generate keys: %v", err)
		}
		log.Println("VAPID keys generated and saved to", keyPath)
	} else {
		signer, err = keys.NewFileSigner(keyPath)
		if err != nil {
			log.Fatalf("Failed to load keys: %v", err)
		}
		log.Println("VAPID keys loaded from", keyPath)
	}

	log.Println("VAPID Public Key:", signer.PublicKeyBase64())

	// Initialize SQLite storage
	store, err = storage.NewSQLite(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()
	log.Println("SQLite storage initialized at", dbPath)

	// Create web push client
	client = webpush.NewClient(signer, subject)

	// Start periodic push sender
	go periodicPush()

	// Set up HTTP handlers
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("Failed to create static file system: %v", err)
	}
	http.Handle("/", http.FileServer(http.FS(staticFS)))
	http.HandleFunc("/api/vapid-public-key", handleVAPIDPublicKey)
	http.HandleFunc("/api/subscribe", handleSubscribe)
	http.HandleFunc("/api/unsubscribe", handleUnsubscribe)
	http.HandleFunc("/ping", handlePing)

	log.Printf("Server starting at %s", serverURL)
	log.Printf("Visit %s to subscribe to push notifications", serverURL)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed: %v", err)
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
		log.Printf("Failed to list subscriptions: %v", err)
		return
	}

	if len(records) == 0 {
		log.Println("No subscribers to notify")
		return
	}

	payload, err := json.Marshal(map[string]string{
		"title": title,
		"body":  body,
	})
	if err != nil {
		log.Printf("Failed to marshal payload: %v", err)
		return
	}

	var sent, failed int
	for _, record := range records {
		err := client.Send(ctx, record.Subscription, payload, &webpush.Options{
			TTL:     3600,
			Urgency: "normal",
		})
		if err != nil {
			log.Printf("Failed to send to %s: %v", record.ID, err)
			failed++
			// Clean up expired/invalid subscriptions (410 Gone)
			if isGone(err) {
				if delErr := store.Delete(ctx, record.ID); delErr != nil {
					log.Printf("Failed to delete expired subscription: %v", delErr)
				} else {
					log.Printf("Deleted expired subscription: %s", record.ID)
				}
			}
		} else {
			sent++
		}
	}

	log.Printf("Push sent: %d successful, %d failed", sent, failed)
}

func isGone(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "410") || strings.Contains(err.Error(), "Gone"))
}

// HTTP Handlers

func handleVAPIDPublicKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"publicKey": signer.PublicKeyBase64(),
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

	log.Printf("New subscription: %s", record.ID)

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

	log.Printf("Unsubscribed: %s", req.Endpoint)

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
