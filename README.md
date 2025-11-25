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
store.List(ctx, limit, offset)
store.Delete(ctx, id)
store.DeleteByEndpoint(ctx, endpoint)
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
    Delete(ctx context.Context, id string) error
    DeleteByEndpoint(ctx context.Context, endpoint string) error
    List(ctx context.Context, limit, offset int) ([]*Record, error)
    Close() error
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