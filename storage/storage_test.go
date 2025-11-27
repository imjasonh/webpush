package storage

import (
	"context"
	"testing"

	"github.com/imjasonh/webpush"
)

func TestMemory(t *testing.T) {
	testStorage(t, NewMemory())
}

func TestSQLite(t *testing.T) {
	// Use in-memory SQLite for testing
	storage, err := NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite() error = %v", err)
	}
	defer storage.Close()

	testStorage(t, storage)
}

func testStorage(t *testing.T, s Storage) {
	ctx := context.Background()

	// Test Save and Get
	record := &Record{
		ID:     "test-id-1",
		UserID: "user-1",
		Subscription: &webpush.Subscription{
			Endpoint: "https://push.example.com/abc123",
			Keys: webpush.Keys{
				P256dh: "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM",
				Auth:   "tBHItJI5svbpez7KI4CCXg",
			},
		},
	}

	if err := s.Save(ctx, record); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Get by ID
	got, err := s.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.ID != record.ID {
		t.Errorf("Get() ID = %q, want %q", got.ID, record.ID)
	}
	if got.UserID != record.UserID {
		t.Errorf("Get() UserID = %q, want %q", got.UserID, record.UserID)
	}
	if got.Subscription.Endpoint != record.Subscription.Endpoint {
		t.Errorf("Get() Endpoint = %q, want %q", got.Subscription.Endpoint, record.Subscription.Endpoint)
	}
	if got.CreatedAt.IsZero() {
		t.Error("Get() CreatedAt is zero")
	}

	// Get by endpoint
	got, err = s.GetByEndpoint(ctx, record.Subscription.Endpoint)
	if err != nil {
		t.Fatalf("GetByEndpoint() error = %v", err)
	}
	if got.ID != record.ID {
		t.Errorf("GetByEndpoint() ID = %q, want %q", got.ID, record.ID)
	}

	// Get by user ID
	records, err := s.GetByUserID(ctx, record.UserID)
	if err != nil {
		t.Fatalf("GetByUserID() error = %v", err)
	}
	if len(records) != 1 {
		t.Errorf("GetByUserID() count = %d, want 1", len(records))
	}

	// Add another record for same user
	record2 := &Record{
		ID:     "test-id-2",
		UserID: "user-1",
		Subscription: &webpush.Subscription{
			Endpoint: "https://push.example.com/def456",
			Keys: webpush.Keys{
				P256dh: "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM",
				Auth:   "tBHItJI5svbpez7KI4CCXg",
			},
		},
	}
	if err := s.Save(ctx, record2); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Get by user ID should return 2
	records, err = s.GetByUserID(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetByUserID() error = %v", err)
	}
	if len(records) != 2 {
		t.Errorf("GetByUserID() count = %d, want 2", len(records))
	}

	// List
	records, err = s.List(ctx, 10, 0)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(records) != 2 {
		t.Errorf("List() count = %d, want 2", len(records))
	}

	// List with pagination
	records, err = s.List(ctx, 1, 0)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(records) != 1 {
		t.Errorf("List(limit=1) count = %d, want 1", len(records))
	}

	// Delete by ID
	if err := s.Delete(ctx, record.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify deleted
	_, err = s.Get(ctx, record.ID)
	if err != ErrNotFound {
		t.Errorf("Get() after delete error = %v, want ErrNotFound", err)
	}

	// Delete by endpoint
	if err := s.DeleteByEndpoint(ctx, record2.Subscription.Endpoint); err != nil {
		t.Fatalf("DeleteByEndpoint() error = %v", err)
	}

	// Verify deleted
	_, err = s.GetByEndpoint(ctx, record2.Subscription.Endpoint)
	if err != ErrNotFound {
		t.Errorf("GetByEndpoint() after delete error = %v, want ErrNotFound", err)
	}

	// List should be empty now
	records, err = s.List(ctx, 10, 0)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(records) != 0 {
		t.Errorf("List() count = %d, want 0", len(records))
	}
}

func TestMemory_NotFound(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()

	_, err := s.Get(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("Get() error = %v, want ErrNotFound", err)
	}

	_, err = s.GetByEndpoint(ctx, "https://nonexistent")
	if err != ErrNotFound {
		t.Errorf("GetByEndpoint() error = %v, want ErrNotFound", err)
	}

	err = s.Delete(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("Delete() error = %v, want ErrNotFound", err)
	}

	err = s.DeleteByEndpoint(ctx, "https://nonexistent")
	if err != ErrNotFound {
		t.Errorf("DeleteByEndpoint() error = %v, want ErrNotFound", err)
	}
}

func TestMemory_Update(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()

	record := &Record{
		ID:     "test-id",
		UserID: "user-1",
		Subscription: &webpush.Subscription{
			Endpoint: "https://push.example.com/abc123",
			Keys: webpush.Keys{
				P256dh: "key1",
				Auth:   "auth1",
			},
		},
	}

	if err := s.Save(ctx, record); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Update
	record.UserID = "user-2"
	record.Subscription.Endpoint = "https://push.example.com/new"

	if err := s.Save(ctx, record); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, err := s.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if got.UserID != "user-2" {
		t.Errorf("Get() UserID = %q, want %q", got.UserID, "user-2")
	}
	if got.Subscription.Endpoint != "https://push.example.com/new" {
		t.Errorf("Get() Endpoint = %q, want %q", got.Subscription.Endpoint, "https://push.example.com/new")
	}
}

func TestSQLite_NotFound(t *testing.T) {
	s, err := NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite() error = %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	_, err = s.Get(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("Get() error = %v, want ErrNotFound", err)
	}

	_, err = s.GetByEndpoint(ctx, "https://nonexistent")
	if err != ErrNotFound {
		t.Errorf("GetByEndpoint() error = %v, want ErrNotFound", err)
	}

	err = s.Delete(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("Delete() error = %v, want ErrNotFound", err)
	}

	err = s.DeleteByEndpoint(ctx, "https://nonexistent")
	if err != ErrNotFound {
		t.Errorf("DeleteByEndpoint() error = %v, want ErrNotFound", err)
	}
}

func TestMemory_VAPIDKey(t *testing.T) {
	testVAPIDKey(t, NewMemory())
}

func TestSQLite_VAPIDKey(t *testing.T) {
	s, err := NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite() error = %v", err)
	}
	defer s.Close()

	testVAPIDKey(t, s)
}

func testVAPIDKey(t *testing.T, s Storage) {
	ctx := context.Background()

	// Create subscriptions with different VAPID keys
	records := []*Record{
		{
			ID:       "sub-1",
			UserID:   "user-1",
			VAPIDKey: "key1-base64",
			Subscription: &webpush.Subscription{
				Endpoint: "https://push.example.com/1",
				Keys:     webpush.Keys{P256dh: "p256dh-1", Auth: "auth-1"},
			},
		},
		{
			ID:       "sub-2",
			UserID:   "user-1",
			VAPIDKey: "key1-base64",
			Subscription: &webpush.Subscription{
				Endpoint: "https://push.example.com/2",
				Keys:     webpush.Keys{P256dh: "p256dh-2", Auth: "auth-2"},
			},
		},
		{
			ID:       "sub-3",
			UserID:   "user-2",
			VAPIDKey: "key2-base64",
			Subscription: &webpush.Subscription{
				Endpoint: "https://push.example.com/3",
				Keys:     webpush.Keys{P256dh: "p256dh-3", Auth: "auth-3"},
			},
		},
	}

	for _, record := range records {
		if err := s.Save(ctx, record); err != nil {
			t.Fatalf("Save() error = %v", err)
		}
	}

	// Test GetByVAPIDKey for key1
	key1Records, err := s.GetByVAPIDKey(ctx, "key1-base64")
	if err != nil {
		t.Fatalf("GetByVAPIDKey(key1) error = %v", err)
	}
	if len(key1Records) != 2 {
		t.Errorf("GetByVAPIDKey(key1) count = %d, want 2", len(key1Records))
	}

	// Test GetByVAPIDKey for key2
	key2Records, err := s.GetByVAPIDKey(ctx, "key2-base64")
	if err != nil {
		t.Fatalf("GetByVAPIDKey(key2) error = %v", err)
	}
	if len(key2Records) != 1 {
		t.Errorf("GetByVAPIDKey(key2) count = %d, want 1", len(key2Records))
	}

	// Test GetByVAPIDKey for non-existent key
	unknownRecords, err := s.GetByVAPIDKey(ctx, "unknown-key")
	if err != nil {
		t.Fatalf("GetByVAPIDKey(unknown) error = %v", err)
	}
	if len(unknownRecords) != 0 {
		t.Errorf("GetByVAPIDKey(unknown) count = %d, want 0", len(unknownRecords))
	}

	// Test that VAPIDKey is preserved on retrieval
	got, err := s.Get(ctx, "sub-1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.VAPIDKey != "key1-base64" {
		t.Errorf("Get().VAPIDKey = %q, want %q", got.VAPIDKey, "key1-base64")
	}

	// Test update preserves VAPIDKey
	got.UserID = "user-updated"
	if err := s.Save(ctx, got); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got2, err := s.Get(ctx, "sub-1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got2.VAPIDKey != "key1-base64" {
		t.Errorf("Get() after update VAPIDKey = %q, want %q", got2.VAPIDKey, "key1-base64")
	}
	if got2.UserID != "user-updated" {
		t.Errorf("Get() after update UserID = %q, want %q", got2.UserID, "user-updated")
	}

	// Test CountByVAPIDKey for key1
	count, err := s.CountByVAPIDKey(ctx, "key1-base64")
	if err != nil {
		t.Fatalf("CountByVAPIDKey(key1) error = %v", err)
	}
	if count != 2 {
		t.Errorf("CountByVAPIDKey(key1) = %d, want 2", count)
	}

	// Test CountByVAPIDKey for key2
	count, err = s.CountByVAPIDKey(ctx, "key2-base64")
	if err != nil {
		t.Fatalf("CountByVAPIDKey(key2) error = %v", err)
	}
	if count != 1 {
		t.Errorf("CountByVAPIDKey(key2) = %d, want 1", count)
	}

	// Test CountByVAPIDKey for non-existent key
	count, err = s.CountByVAPIDKey(ctx, "unknown-key")
	if err != nil {
		t.Fatalf("CountByVAPIDKey(unknown) error = %v", err)
	}
	if count != 0 {
		t.Errorf("CountByVAPIDKey(unknown) = %d, want 0", count)
	}
}
