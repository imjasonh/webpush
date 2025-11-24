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
	"encoding/json"
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
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/sw.js", handleServiceWorker)
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

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(indexHTML))
}

func handleServiceWorker(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Write([]byte(serviceWorkerJS))
}

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

// Static content

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Push Demo</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        h1 { color: #333; }
        button {
            background: #007bff;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            margin: 5px;
        }
        button:hover { background: #0056b3; }
        button:disabled { background: #ccc; cursor: not-allowed; }
        button.danger { background: #dc3545; }
        button.danger:hover { background: #c82333; }
        button.success { background: #28a745; }
        #status {
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
        }
        .success { background: #d4edda; color: #155724; }
        .error { background: #f8d7da; color: #721c24; }
        .info { background: #cce5ff; color: #004085; }
    </style>
</head>
<body>
    <div class="card">
        <h1>🔔 Web Push Demo</h1>
        <p>Subscribe to receive push notifications from this server.</p>
        <p>Notifications are sent:</p>
        <ul>
            <li>Every minute automatically</li>
            <li>When someone visits <a href="/ping">/ping</a></li>
        </ul>
    </div>

    <div class="card">
        <h2>Subscription</h2>
        <button id="subscribeBtn" onclick="subscribe()">Subscribe to Notifications</button>
        <button id="unsubscribeBtn" onclick="unsubscribe()" class="danger" disabled>Unsubscribe</button>
        <div id="status"></div>
    </div>

    <div class="card">
        <h2>Test Push</h2>
        <button onclick="sendPing()" class="success">Send Ping to All Subscribers</button>
    </div>

    <script>
        let vapidPublicKey = '';
        let currentSubscription = null;

        // Convert base64 to Uint8Array
        function urlBase64ToUint8Array(base64String) {
            const padding = '='.repeat((4 - base64String.length % 4) % 4);
            const base64 = (base64String + padding)
                .replace(/-/g, '+')
                .replace(/_/g, '/');
            const rawData = window.atob(base64);
            const outputArray = new Uint8Array(rawData.length);
            for (let i = 0; i < rawData.length; ++i) {
                outputArray[i] = rawData.charCodeAt(i);
            }
            return outputArray;
        }

        function setStatus(message, type) {
            const status = document.getElementById('status');
            status.textContent = message;
            status.className = type;
        }

        async function init() {
            // Get VAPID public key
            const resp = await fetch('/api/vapid-public-key');
            const data = await resp.json();
            vapidPublicKey = data.publicKey;

            // Check if already subscribed
            if ('serviceWorker' in navigator && 'PushManager' in window) {
                const registration = await navigator.serviceWorker.register('/sw.js');
                const subscription = await registration.pushManager.getSubscription();
                if (subscription) {
                    currentSubscription = subscription;
                    document.getElementById('subscribeBtn').disabled = true;
                    document.getElementById('unsubscribeBtn').disabled = false;
                    setStatus('You are subscribed to notifications', 'success');
                }
            } else {
                setStatus('Push notifications not supported in this browser', 'error');
                document.getElementById('subscribeBtn').disabled = true;
            }
        }

        async function subscribe() {
            try {
                const permission = await Notification.requestPermission();
                if (permission !== 'granted') {
                    setStatus('Notification permission denied', 'error');
                    return;
                }

                const registration = await navigator.serviceWorker.ready;
                const subscription = await registration.pushManager.subscribe({
                    userVisibleOnly: true,
                    applicationServerKey: urlBase64ToUint8Array(vapidPublicKey)
                });

                // Send to server
                const resp = await fetch('/api/subscribe', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(subscription.toJSON())
                });

                if (resp.ok) {
                    currentSubscription = subscription;
                    document.getElementById('subscribeBtn').disabled = true;
                    document.getElementById('unsubscribeBtn').disabled = false;
                    setStatus('Successfully subscribed!', 'success');
                } else {
                    setStatus('Failed to subscribe: ' + await resp.text(), 'error');
                }
            } catch (err) {
                setStatus('Error: ' + err.message, 'error');
            }
        }

        async function unsubscribe() {
            try {
                if (currentSubscription) {
                    await fetch('/api/unsubscribe', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ endpoint: currentSubscription.endpoint })
                    });
                    await currentSubscription.unsubscribe();
                    currentSubscription = null;
                }
                document.getElementById('subscribeBtn').disabled = false;
                document.getElementById('unsubscribeBtn').disabled = true;
                setStatus('Successfully unsubscribed', 'info');
            } catch (err) {
                setStatus('Error: ' + err.message, 'error');
            }
        }

        async function sendPing() {
            try {
                const resp = await fetch('/ping');
                if (resp.ok) {
                    setStatus('Ping sent to all subscribers!', 'success');
                } else {
                    setStatus('Failed to send ping', 'error');
                }
            } catch (err) {
                setStatus('Error: ' + err.message, 'error');
            }
        }

        init();
    </script>
</body>
</html>
`

const serviceWorkerJS = `
self.addEventListener('push', function(event) {
    let data = { title: 'Notification', body: '' };
    
    if (event.data) {
        try {
            data = event.data.json();
        } catch (e) {
            data.body = event.data.text();
        }
    }

    const options = {
        body: data.body || '',
        icon: data.icon || '',
        badge: data.badge || '',
        data: data.data || {},
        requireInteraction: false
    };

    event.waitUntil(
        self.registration.showNotification(data.title || 'Notification', options)
    );
});

self.addEventListener('notificationclick', function(event) {
    event.notification.close();
    
    if (event.notification.data && event.notification.data.url) {
        event.waitUntil(
            clients.openWindow(event.notification.data.url)
        );
    }
});
`
