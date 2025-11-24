# Web Push Example

A complete example demonstrating the web push library with:
- VAPID keys stored on disk (auto-generated on first run)
- SQLite storage for subscriptions
- Web client for subscribing to notifications
- Automatic push every minute
- Manual push via `/ping` endpoint

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

## Files Generated

On first run, the example generates:
- `vapid-private.pem` - VAPID private key (keep this secret!)
- `subscriptions.db` - SQLite database for storing subscriptions

## Endpoints

- `GET /` - Web client UI
- `GET /sw.js` - Service worker for handling push events
- `GET /api/vapid-public-key` - Returns the VAPID public key
- `POST /api/subscribe` - Register a new subscription
- `POST /api/unsubscribe` - Remove a subscription
- `GET /ping` - Send push to all subscribers (optional `?title=` and `?body=` query params)
