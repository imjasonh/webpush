# Web Push Example

A complete example demonstrating the web push library with:
- VAPID keys stored on disk (auto-generated on first run)
- SQLite storage for subscriptions
- Web client for subscribing to notifications
- Automatic push every minute
- Manual push via `/ping` endpoint
- **Key rotation detection and client-side resubscription**

## Running

```bash
cd example
go run main.go
```

Then open http://localhost:8080 in your browser.

## Features

1. **Subscribe**: Click "Subscribe to Notifications" to register for push notifications
2. **Automatic Pushes**: Notifications are sent every minute to all subscribers
3. **Manual Pushes**: Visit `/ping` or click "Send Ping" to trigger an immediate push
4. **Key Rotation Support**: Client automatically detects when the VAPID key changes and prompts for resubscription

## Key Rotation

When VAPID keys are rotated on the server, existing browser subscriptions become invalid (they are bound to the applicationServerKey). This example demonstrates how to handle this:

### Server-side
The `/api/vapid-public-key` endpoint returns both the public key and a `keyId` (truncated key fingerprint) that clients can use to detect changes.

### Client-side
1. The client stores the `keyId` in localStorage when subscribing
2. On page load and periodically, the client checks if the server's `keyId` has changed
3. If changed, a "Resubscribe" button appears prompting the user to resubscribe
4. The `resubscribe()` function:
   - Unsubscribes the old (invalid) subscription
   - Notifies the server to remove the old subscription record
   - Creates a new subscription with the new VAPID key

### Service Worker
The service worker listens for `pushsubscriptionchange` events (triggered by the browser when a subscription becomes invalid) and notifies open windows.

## Files Generated

On first run, the example generates:
- `vapid-private.pem` - VAPID private key (keep this secret!)
- `subscriptions.db` - SQLite database for storing subscriptions

## Endpoints

- `GET /` - Web client UI
- `GET /sw.js` - Service worker for handling push events
- `GET /api/vapid-public-key` - Returns the VAPID public key and keyId
- `POST /api/subscribe` - Register a new subscription
- `POST /api/unsubscribe` - Remove a subscription
- `GET /ping` - Send push to all subscribers (optional `?title=` and `?body=` query params)
