package storage

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/imjasonh/webpush"
)

// ErrNotFound is returned when a record is not found.
var ErrNotFound = errors.New("record not found")

// Memory implements in-memory storage for testing and development.
type Memory struct {
	mu      sync.RWMutex
	records map[string]*Record
}

// NewMemory creates a new in-memory storage.
func NewMemory() *Memory {
	return &Memory{
		records: make(map[string]*Record),
	}
}

// Save stores or updates a subscription.
func (m *Memory) Save(_ context.Context, record *Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.UpdatedAt = now

	// Make a copy to avoid external mutations
	stored := &Record{
		ID:        record.ID,
		UserID:    record.UserID,
		CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt,
		VAPIDKey:  record.VAPIDKey,
		Subscription: &webpush.Subscription{
			Endpoint: record.Subscription.Endpoint,
			Keys: webpush.Keys{
				P256dh: record.Subscription.Keys.P256dh,
				Auth:   record.Subscription.Keys.Auth,
			},
		},
	}
	m.records[record.ID] = stored
	return nil
}

// Get retrieves a subscription by ID.
func (m *Memory) Get(_ context.Context, id string) (*Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	record, ok := m.records[id]
	if !ok {
		return nil, ErrNotFound
	}
	return copyRecord(record), nil
}

// GetByEndpoint retrieves a subscription by its endpoint URL.
func (m *Memory) GetByEndpoint(_ context.Context, endpoint string) (*Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, record := range m.records {
		if record.Subscription.Endpoint == endpoint {
			return copyRecord(record), nil
		}
	}
	return nil, ErrNotFound
}

// GetByUserID retrieves all subscriptions for a user.
func (m *Memory) GetByUserID(_ context.Context, userID string) ([]*Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []*Record
	for _, record := range m.records {
		if record.UserID == userID {
			results = append(results, copyRecord(record))
		}
	}
	return results, nil
}

// GetByVAPIDKey retrieves all subscriptions for a specific VAPID key.
func (m *Memory) GetByVAPIDKey(_ context.Context, vapidKey string) ([]*Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []*Record
	for _, record := range m.records {
		if record.VAPIDKey == vapidKey {
			results = append(results, copyRecord(record))
		}
	}
	return results, nil
}

// CountByVAPIDKey returns the number of subscriptions for a specific VAPID key.
func (m *Memory) CountByVAPIDKey(_ context.Context, vapidKey string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, record := range m.records {
		if record.VAPIDKey == vapidKey {
			count++
		}
	}
	return count, nil
}

// Delete removes a subscription by ID.
func (m *Memory) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.records[id]; !ok {
		return ErrNotFound
	}
	delete(m.records, id)
	return nil
}

// DeleteByEndpoint removes a subscription by its endpoint URL.
func (m *Memory) DeleteByEndpoint(_ context.Context, endpoint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, record := range m.records {
		if record.Subscription.Endpoint == endpoint {
			delete(m.records, id)
			return nil
		}
	}
	return ErrNotFound
}

// List returns all subscriptions with pagination.
func (m *Memory) List(_ context.Context, limit, offset int) ([]*Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Collect all records
	var all []*Record
	for _, record := range m.records {
		all = append(all, record)
	}

	// Apply pagination
	if offset >= len(all) {
		return nil, nil
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}

	results := make([]*Record, 0, end-offset)
	for i := offset; i < end; i++ {
		results = append(results, copyRecord(all[i]))
	}
	return results, nil
}

// Close is a no-op for in-memory storage.
func (m *Memory) Close() error {
	return nil
}

func copyRecord(r *Record) *Record {
	return &Record{
		ID:        r.ID,
		UserID:    r.UserID,
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
		VAPIDKey:  r.VAPIDKey,
		Subscription: &webpush.Subscription{
			Endpoint: r.Subscription.Endpoint,
			Keys: webpush.Keys{
				P256dh: r.Subscription.Keys.P256dh,
				Auth:   r.Subscription.Keys.Auth,
			},
		},
	}
}
