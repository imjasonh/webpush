# webpush

A Go library for sending [Web Push API](https://developer.mozilla.org/en-US/docs/Web/API/Push_API) notifications with [VAPID](https://datatracker.ietf.org/doc/html/rfc8292) authentication.

## Features

- RFC 8291 compliant message encryption (aes128gcm)
- RFC 8292 VAPID authentication
- Pluggable VAPID key providers:
  - File-based (PEM or base64 encoded)
  - Google Cloud KMS
- Pluggable subscription storage:
  - In-memory (for testing/development)
  - SQLite
- Easy integration with JavaScript Push API clients

## Installation

```bash
go get github.com/imjasonh/webpush
```

## Quick Start

### 1. Generate VAPID Keys

```go
package main

import (
    "fmt"
    "github.com/imjasonh/webpush/keys"
)

func main() {
    // Generate a new key pair and get base64-encoded keys
    privateKey, publicKey, err := keys.GenerateKeyPair()
    if err != nil {
        panic(err)
    }
    
    fmt.Println("Private Key:", privateKey)
    fmt.Println("Public Key:", publicKey)
    
    // Or generate and save to a PEM file
    signer, err := keys.GenerateKey("vapid-private.pem")
    if err != nil {
        panic(err)
    }
    fmt.Println("Public Key:", signer.PublicKeyBase64())
}
```

### 2. Send Push Notifications

```go
package main

import (
    "context"
    "github.com/imjasonh/webpush"
    "github.com/imjasonh/webpush/keys"
)

func main() {
    // Load VAPID keys
    signer, err := keys.NewFileSigner("vapid-private.pem")
    // Or from base64: signer, err := keys.NewFileSignerFromBase64("your-base64-private-key")
    if err != nil {
        panic(err)
    }

    // Create client with VAPID subject (must be mailto: or https: URL)
    client := webpush.NewClient(signer, "mailto:admin@example.com")

    // Parse subscription from client
    sub, err := webpush.ParseSubscription([]byte(`{
        "endpoint": "https://fcm.googleapis.com/fcm/send/...",
        "keys": {
            "p256dh": "...",
            "auth": "..."
        }
    }`))
    if err != nil {
        panic(err)
    }

    // Send notification
    err = client.Send(context.Background(), sub, []byte(`{"title":"Hello","body":"World"}`), &webpush.Options{
        TTL:     3600,       // Time-to-live in seconds
        Urgency: "high",    // very-low, low, normal, high
        Topic:   "updates", // For message collapsing
    })
    if err != nil {
        panic(err)
    }
}
```

### 3. Store Subscriptions

```go
package main

import (
    "context"
    "github.com/google/uuid"
    "github.com/imjasonh/webpush"
    "github.com/imjasonh/webpush/storage"
)

func main() {
    // Use SQLite for production
    store, err := storage.NewSQLite("subscriptions.db")
    // Or use in-memory for testing: store := storage.NewMemory()
    if err != nil {
        panic(err)
    }
    defer store.Close()

    // Save a subscription
    sub := &webpush.Subscription{
        Endpoint: "https://fcm.googleapis.com/fcm/send/...",
        Keys: webpush.Keys{
            P256dh: "...",
            Auth:   "...",
        },
    }

    record := &storage.Record{
        ID:           uuid.New().String(),
        UserID:       "user-123", // Optional: associate with your user
        Subscription: sub,
    }

    err = store.Save(context.Background(), record)
    if err != nil {
        panic(err)
    }

    // Get subscriptions for a user
    records, err := store.GetByUserID(context.Background(), "user-123")
    if err != nil {
        panic(err)
    }
    
    // Send to all user's devices
    for _, r := range records {
        // client.Send(ctx, r.Subscription, payload, opts)
    }
}
```

## Using Google Cloud KMS

For production environments, you can store your VAPID private key in Google Cloud KMS:

```go
package main

import (
    "context"
    "github.com/imjasonh/webpush"
    "github.com/imjasonh/webpush/keys"
)

func main() {
    ctx := context.Background()
    
    // Key name format: projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}/cryptoKeyVersions/{version}
    keyName := "projects/my-project/locations/global/keyRings/webpush/cryptoKeys/vapid/cryptoKeyVersions/1"
    
    signer, err := keys.NewKMSSigner(ctx, keyName)
    if err != nil {
        panic(err)
    }
    defer signer.Close()

    client := webpush.NewClient(signer, "mailto:admin@example.com")
    // Use client as normal...
}
```

### Creating a KMS Key

```bash
# Create a key ring
gcloud kms keyrings create webpush --location=global

# Create an EC P-256 signing key
gcloud kms keys create vapid \
    --keyring=webpush \
    --location=global \
    --purpose=asymmetric-signing \
    --default-algorithm=ec-sign-p256-sha256
```

## JavaScript Client Integration

### Service Worker Setup

1. Create a service worker file (`sw.js`):

```javascript
self.addEventListener('push', function(event) {
    const data = event.data ? event.data.json() : {};
    const title = data.title || 'Notification';
    const options = {
        body: data.body || '',
        icon: data.icon || '/icon.png',
        badge: data.badge || '/badge.png',
        data: data.data || {}
    };
    
    event.waitUntil(
        self.registration.showNotification(title, options)
    );
});

self.addEventListener('notificationclick', function(event) {
    event.notification.close();
    
    // Handle notification click
    if (event.notification.data && event.notification.data.url) {
        event.waitUntil(
            clients.openWindow(event.notification.data.url)
        );
    }
});
```

2. Register the service worker and subscribe to push:

```javascript
// Your VAPID public key from the server (base64 URL-safe encoded)
const VAPID_PUBLIC_KEY = 'YOUR_PUBLIC_KEY_HERE';

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

async function subscribeToNotifications() {
    // Register service worker
    const registration = await navigator.serviceWorker.register('/sw.js');
    
    // Wait for service worker to be ready
    await navigator.serviceWorker.ready;
    
    // Subscribe to push notifications
    const subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(VAPID_PUBLIC_KEY)
    });
    
    // Send subscription to your server
    await fetch('/api/subscribe', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(subscription)
    });
    
    console.log('Subscribed to push notifications');
}

// Request permission and subscribe
async function enableNotifications() {
    const permission = await Notification.requestPermission();
    if (permission === 'granted') {
        await subscribeToNotifications();
    }
}
```

3. Create a simple server endpoint to receive subscriptions:

```go
package main

import (
    "context"
    "encoding/json"
    "net/http"
    
    "github.com/google/uuid"
    "github.com/imjasonh/webpush"
    "github.com/imjasonh/webpush/keys"
    "github.com/imjasonh/webpush/storage"
)

var (
    store  storage.Storage
    client *webpush.Client
)

func main() {
    // Initialize storage
    var err error
    store, err = storage.NewSQLite("subscriptions.db")
    if err != nil {
        panic(err)
    }
    defer store.Close()

    // Initialize VAPID signer
    signer, err := keys.NewFileSigner("vapid-private.pem")
    if err != nil {
        panic(err)
    }
    
    client = webpush.NewClient(signer, "mailto:admin@example.com")

    // Serve static files
    http.Handle("/", http.FileServer(http.Dir("static")))
    
    // API endpoints
    http.HandleFunc("/api/vapid-public-key", handleVAPIDPublicKey)
    http.HandleFunc("/api/subscribe", handleSubscribe)
    http.HandleFunc("/api/push", handlePush)
    
    http.ListenAndServe(":8080", nil)
}

func handleVAPIDPublicKey(w http.ResponseWriter, r *http.Request) {
    // Return the public key for the JavaScript client
    signer, _ := keys.NewFileSigner("vapid-private.pem")
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
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Validate subscription
    if sub.Endpoint == "" || sub.Keys.P256dh == "" || sub.Keys.Auth == "" {
        http.Error(w, "Invalid subscription", http.StatusBadRequest)
        return
    }

    // Check if subscription already exists
    existing, err := store.GetByEndpoint(r.Context(), sub.Endpoint)
    if err == nil {
        // Already subscribed
        json.NewEncoder(w).Encode(map[string]string{"id": existing.ID})
        return
    }

    // Save new subscription
    record := &storage.Record{
        ID:           uuid.New().String(),
        Subscription: &sub,
    }
    
    if err := store.Save(r.Context(), record); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"id": record.ID})
}

func handlePush(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var req struct {
        Title string `json:"title"`
        Body  string `json:"body"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    payload, _ := json.Marshal(req)

    // Get all subscriptions
    records, err := store.List(r.Context(), 1000, 0)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Send to all subscriptions
    ctx := context.Background()
    var sent, failed int
    for _, record := range records {
        err := client.Send(ctx, record.Subscription, payload, nil)
        if err != nil {
            failed++
            // If subscription is gone (410), delete it
            // if strings.Contains(err.Error(), "410") {
            //     store.Delete(ctx, record.ID)
            // }
        } else {
            sent++
        }
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]int{
        "sent":   sent,
        "failed": failed,
    })
}
```

## API Reference

### Types

#### `Subscription`

```go
type Subscription struct {
    Endpoint string `json:"endpoint"`
    Keys     Keys   `json:"keys"`
}

type Keys struct {
    P256dh string `json:"p256dh"`
    Auth   string `json:"auth"`
}
```

#### `Options`

```go
type Options struct {
    TTL     int    // Time-to-live in seconds (default: 2419200 = 4 weeks)
    Urgency string // Urgency: very-low, low, normal, high
    Topic   string // Topic for message replacement
}
```

### Client

```go
// Create a new client
client := webpush.NewClient(signer, subject)

// Optionally set custom HTTP client
client.WithHTTPClient(httpClient)

// Send a notification
err := client.Send(ctx, subscription, payload, options)

// Parse subscription from JSON
sub, err := webpush.ParseSubscription(jsonBytes)
```

### Key Providers

```go
// File-based (PEM)
signer, err := keys.NewFileSigner("path/to/key.pem")

// File-based (base64)
signer, err := keys.NewFileSignerFromBase64("base64-private-key")

// Google Cloud KMS
signer, err := keys.NewKMSSigner(ctx, "projects/.../cryptoKeyVersions/1")
defer signer.Close()

// Generate new keys
signer, err := keys.GenerateKey("path/to/save.pem")
privateB64, publicB64, err := keys.GenerateKeyPair()
```

### Storage

```go
// In-memory (for testing)
store := storage.NewMemory()

// SQLite
store, err := storage.NewSQLite("subscriptions.db")
defer store.Close()

// Operations
err := store.Save(ctx, record)
record, err := store.Get(ctx, id)
record, err := store.GetByEndpoint(ctx, endpoint)
records, err := store.GetByUserID(ctx, userID)
records, err := store.List(ctx, limit, offset)
err := store.Delete(ctx, id)
err := store.DeleteByEndpoint(ctx, endpoint)
```

## Custom Storage Implementation

Implement the `storage.Storage` interface:

```go
type Storage interface {
    Save(ctx context.Context, record *Record) error
    Get(ctx context.Context, id string) (*Record, error)
    GetByEndpoint(ctx context.Context, endpoint string) (*Record, error)
    GetByUserID(ctx context.Context, userID string) ([]*Record, error)
    Delete(ctx context.Context, id string) error
    DeleteByEndpoint(ctx context.Context, endpoint string) error
    List(ctx context.Context, limit, offset int) ([]*Record, error)
    Close() error
}
```

## Custom Key Provider

Implement the `webpush.Signer` interface:

```go
type Signer interface {
    Sign(ctx context.Context, data []byte) ([]byte, error)
    PublicKey() []byte
}
```

The `Sign` method receives SHA-256 hash and should return IEEE P1363 format signature (64 bytes for P-256).

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.