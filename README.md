# webpush

A Go library for sending [Web Push API](https://developer.mozilla.org/en-US/docs/Web/API/Push_API) notifications with [VAPID](https://datatracker.ietf.org/doc/html/rfc8292) authentication.

## Features

- RFC 8291 compliant message encryption (aes128gcm)
- RFC 8292 VAPID authentication
- Pluggable VAPID key providers:
  - File-based (PEM or base64 encoded)
  - Google Cloud KMS
  - Rotating key manager for key rotation
- Pluggable subscription storage:
  - In-memory (for testing/development)
  - SQLite
- Key rotation support with subscription tracking
- Easy integration with JavaScript Push API clients

## Installation

```bash
go get github.com/imjasonh/webpush
```

## Quick Start

See the [example/](example/) directory for a complete working demo with:
- VAPID key generation and storage on disk
- SQLite subscription storage
- Web client with service worker for push notifications
- Automatic periodic notifications and manual `/ping` endpoint

To run the example:

```bash
cd example
go run main.go
```

Then open http://localhost:8080 in your browser.

## Basic Usage

```go
package main

import (
    "context"
    "github.com/imjasonh/webpush"
    "github.com/imjasonh/webpush/keys"
)

func main() {
    // Load or generate VAPID keys
    signer, err := keys.NewFileSigner("vapid-private.pem")
    if err != nil {
        panic(err)
    }

    // Create client with VAPID subject (must be mailto: or https: URL)
    client := webpush.NewClient(signer, "mailto:admin@example.com")

    // Parse subscription from client (received from browser)
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
        TTL:     3600,
        Urgency: "high",
    })
    if err != nil {
        panic(err)
    }
}
```

## Using Google Cloud KMS

For production environments, you can store your VAPID private key in Google Cloud KMS:

```go
signer, err := keys.NewKMSSigner(ctx, "projects/my-project/locations/global/keyRings/webpush/cryptoKeys/vapid/cryptoKeyVersions/1")
if err != nil {
    panic(err)
}
defer signer.Close()

client := webpush.NewClient(signer, "mailto:admin@example.com")
```

Create a KMS key:

```bash
gcloud kms keyrings create webpush --location=global
gcloud kms keys create vapid \
    --keyring=webpush \
    --location=global \
    --purpose=asymmetric-signing \
    --default-algorithm=ec-sign-p256-sha256
```

## API Reference

### Types

```go
type Subscription struct {
    Endpoint string `json:"endpoint"`
    Keys     Keys   `json:"keys"`
}

type Options struct {
    TTL     int    // Time-to-live in seconds (default: 2419200 = 4 weeks)
    Urgency string // very-low, low, normal, high
    Topic   string // Topic for message replacement
}
```

### Key Providers

```go
// File-based (PEM)
signer, err := keys.NewFileSigner("path/to/key.pem")

// File-based (base64)
signer, err := keys.NewFileSignerFromBase64("base64-private-key")

// Google Cloud KMS
signer, err := keys.NewKMSSigner(ctx, "projects/.../cryptoKeyVersions/1")

// Generate new keys
signer, err := keys.GenerateKey("path/to/save.pem")
privateB64, publicB64, err := keys.GenerateKeyPair()

// Rotating signer for key rotation
rotating := keys.NewRotatingSigner(currentSigner)
```

### Storage

```go
// In-memory (for testing)
store := storage.NewMemory()

// SQLite
store, err := storage.NewSQLite("subscriptions.db")

// Operations
store.Save(ctx, record)
store.Get(ctx, id)
store.GetByEndpoint(ctx, endpoint)
store.GetByUserID(ctx, userID)
store.GetByVAPIDKey(ctx, vapidKeyB64)  // Get subscriptions for a specific VAPID key
store.List(ctx, limit, offset)
store.Delete(ctx, id)
store.DeleteByEndpoint(ctx, endpoint)
```

## Key Rotation

VAPID keys should be rotated periodically for security. When rotating keys, existing browser subscriptions become invalid because they are tied to the VAPID public key (applicationServerKey). The `RotatingSigner` helps manage this transition.

### How Key Rotation Works

1. Browser subscriptions are created using a specific VAPID public key
2. When the VAPID key changes, push services reject notifications with the old key
3. Clients must re-subscribe with the new applicationServerKey

### Using RotatingSigner

```go
// Create a rotating signer with the current key
currentKey, _ := keys.NewFileSigner("current-key.pem")
rotating := keys.NewRotatingSigner(currentKey)

// Create web push client
client := webpush.NewClient(rotating, "mailto:admin@example.com")

// When storing new subscriptions, track which key was used
record := &storage.Record{
    ID:           uuid.New().String(),
    Subscription: sub,
    VAPIDKey:     rotating.PublicKeyBase64(),  // Track the key used
}
store.Save(ctx, record)

// When it's time to rotate (e.g., annually):
newKey, _ := keys.GenerateKey("new-key.pem")
rotating.Rotate(newKey)

// Find subscriptions that need re-subscription
oldKeyB64 := rotating.PreviousKeysBase64()[0]
oldSubscriptions, _ := store.GetByVAPIDKey(ctx, oldKeyB64)
// Notify users to re-subscribe, or delete old subscriptions

// Send notifications - each subscription uses the correct key
records, _ := store.List(ctx, 100, 0)
for _, record := range records {
    if rotating.IsCurrentKeyBase64(record.VAPIDKey) {
        // Can send with current client
        client.Send(ctx, record.Subscription, payload, nil)
    } else {
        // Need to use the old key's signer
        oldSigner := rotating.GetSignerForKeyBase64(record.VAPIDKey)
        if oldSigner != nil {
            oldClient := webpush.NewClient(oldSigner, "mailto:admin@example.com")
            oldClient.Send(ctx, record.Subscription, payload, nil)
        }
    }
}

// After all clients have re-subscribed, remove old keys
rotating.ClearPreviousKeys()
```

### RotatingSigner API

```go
// Create and manage
rotating := keys.NewRotatingSigner(currentKey)
rotating.Rotate(newKey)                    // Add new key, move current to previous
rotating.RemoveOldestKey()                 // Remove the oldest previous key
rotating.ClearPreviousKeys()               // Remove all previous keys

// Query keys
rotating.PublicKey()                       // Current key bytes
rotating.PublicKeyBase64()                 // Current key as base64
rotating.PreviousKeys()                    // Previous key bytes
rotating.PreviousKeysBase64()              // Previous keys as base64
rotating.AllKeys()                         // All keys (current first)
rotating.AllKeysBase64()                   // All keys as base64
rotating.KeyCount()                        // Total number of keys

// Check keys
rotating.IsCurrentKey(pubKey)              // Check if pubKey is current
rotating.IsCurrentKeyBase64(b64Key)        // Check if base64 key is current  
rotating.IsKnownKey(pubKey)                // Check if pubKey is any known key
rotating.IsKnownKeyBase64(b64Key)          // Check if base64 key is known

// Get signer for specific key (for sending to old subscriptions)
signer := rotating.GetSignerForKey(pubKey)
signer := rotating.GetSignerForKeyBase64(b64Key)
```

## Custom Implementations

### Custom Storage

Implement the `storage.Storage` interface:

```go
type Storage interface {
    Save(ctx context.Context, record *Record) error
    Get(ctx context.Context, id string) (*Record, error)
    GetByEndpoint(ctx context.Context, endpoint string) (*Record, error)
    GetByUserID(ctx context.Context, userID string) ([]*Record, error)
    GetByVAPIDKey(ctx context.Context, vapidKey string) ([]*Record, error)
    Delete(ctx context.Context, id string) error
    DeleteByEndpoint(ctx context.Context, endpoint string) error
    List(ctx context.Context, limit, offset int) ([]*Record, error)
    Close() error
}
```

The `Record` struct includes a `VAPIDKey` field to track which VAPID key was used when the subscription was created:

```go
type Record struct {
    ID           string
    UserID       string
    Subscription *webpush.Subscription
    CreatedAt    time.Time
    UpdatedAt    time.Time
    VAPIDKey     string  // Base64-encoded VAPID public key used for this subscription
}
```

### Custom Key Provider

Implement the `webpush.Signer` interface:

```go
type Signer interface {
    Sign(ctx context.Context, data []byte) ([]byte, error)
    PublicKey() []byte
}
```

The `Sign` method receives a SHA-256 hash and should return an IEEE P1363 format signature (64 bytes for P-256).

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.