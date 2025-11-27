// Package storage provides interfaces and implementations for storing
// web push subscriptions.
package storage

import (
	"context"
	"time"

	"github.com/imjasonh/webpush"
)

// Record represents a stored subscription with metadata.
type Record struct {
	ID           string                `json:"id"`
	UserID       string                `json:"user_id,omitempty"`
	Subscription *webpush.Subscription `json:"subscription"`
	CreatedAt    time.Time             `json:"created_at"`
	UpdatedAt    time.Time             `json:"updated_at"`
	// VAPIDKey is the base64-encoded VAPID public key that was used when
	// this subscription was created. This is important for key rotation:
	// when the VAPID key changes, existing subscriptions are invalidated
	// and clients must re-subscribe with the new key.
	VAPIDKey string `json:"vapid_key,omitempty"`
}

// Storage defines the interface for storing web push subscriptions.
type Storage interface {
	// Save stores or updates a subscription.
	Save(ctx context.Context, record *Record) error

	// Get retrieves a subscription by ID.
	Get(ctx context.Context, id string) (*Record, error)

	// GetByEndpoint retrieves a subscription by its endpoint URL.
	GetByEndpoint(ctx context.Context, endpoint string) (*Record, error)

	// GetByUserID retrieves all subscriptions for a user.
	GetByUserID(ctx context.Context, userID string) ([]*Record, error)

	// GetByVAPIDKey retrieves all subscriptions for a specific VAPID key.
	// This is useful during key rotation to identify subscriptions that need
	// to be re-subscribed with the new key.
	GetByVAPIDKey(ctx context.Context, vapidKey string) ([]*Record, error)

	// CountByVAPIDKey returns the number of subscriptions for a specific VAPID key.
	// This is useful for determining if a key can be safely removed during rotation.
	CountByVAPIDKey(ctx context.Context, vapidKey string) (int, error)

	// Delete removes a subscription by ID.
	Delete(ctx context.Context, id string) error

	// DeleteByEndpoint removes a subscription by its endpoint URL.
	DeleteByEndpoint(ctx context.Context, endpoint string) error

	// List returns all subscriptions with pagination.
	List(ctx context.Context, limit, offset int) ([]*Record, error)

	// Close closes the storage connection.
	Close() error
}
