// Package vapid provides VAPID (Voluntary Application Server Identification)
// utilities for Web Push.
package vapid

import (
	"encoding/base64"
)

// ApplicationServerKey returns the VAPID public key formatted for use with
// the JavaScript PushManager.subscribe() method.
func ApplicationServerKey(publicKey []byte) string {
	return base64.RawURLEncoding.EncodeToString(publicKey)
}

// DecodeApplicationServerKey decodes a base64 URL-encoded application server key.
func DecodeApplicationServerKey(key string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(key)
}
