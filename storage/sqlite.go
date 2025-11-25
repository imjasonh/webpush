package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/imjasonh/webpush"
	_ "modernc.org/sqlite" // SQLite driver
)

// SQLite implements storage using SQLite.
type SQLite struct {
	db *sql.DB
}

// NewSQLite creates a new SQLite storage.
// dsn is the data source name, e.g., "webpush.db" or ":memory:".
func NewSQLite(dsn string) (*SQLite, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Create table if it doesn't exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS subscriptions (
			id TEXT PRIMARY KEY,
			user_id TEXT,
			endpoint TEXT NOT NULL UNIQUE,
			p256dh TEXT NOT NULL,
			auth TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_user_id ON subscriptions(user_id);
		CREATE INDEX IF NOT EXISTS idx_endpoint ON subscriptions(endpoint);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("creating table: %w", err)
	}

	return &SQLite{db: db}, nil
}

// Save stores or updates a subscription.
func (s *SQLite) Save(ctx context.Context, record *Record) error {
	now := time.Now()
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.UpdatedAt = now

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO subscriptions (id, user_id, endpoint, p256dh, auth, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			user_id = excluded.user_id,
			endpoint = excluded.endpoint,
			p256dh = excluded.p256dh,
			auth = excluded.auth,
			updated_at = excluded.updated_at
	`,
		record.ID,
		record.UserID,
		record.Subscription.Endpoint,
		record.Subscription.Keys.P256dh,
		record.Subscription.Keys.Auth,
		record.CreatedAt,
		record.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("saving subscription: %w", err)
	}
	return nil
}

// Get retrieves a subscription by ID.
func (s *SQLite) Get(ctx context.Context, id string) (*Record, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, endpoint, p256dh, auth, created_at, updated_at
		FROM subscriptions WHERE id = ?
	`, id)
	return scanRecord(row)
}

// GetByEndpoint retrieves a subscription by its endpoint URL.
func (s *SQLite) GetByEndpoint(ctx context.Context, endpoint string) (*Record, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, endpoint, p256dh, auth, created_at, updated_at
		FROM subscriptions WHERE endpoint = ?
	`, endpoint)
	return scanRecord(row)
}

// GetByUserID retrieves all subscriptions for a user.
func (s *SQLite) GetByUserID(ctx context.Context, userID string) ([]*Record, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, endpoint, p256dh, auth, created_at, updated_at
		FROM subscriptions WHERE user_id = ?
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("querying subscriptions: %w", err)
	}
	defer rows.Close()
	return scanRecords(rows)
}

// Delete removes a subscription by ID.
func (s *SQLite) Delete(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM subscriptions WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("deleting subscription: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteByEndpoint removes a subscription by its endpoint URL.
func (s *SQLite) DeleteByEndpoint(ctx context.Context, endpoint string) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM subscriptions WHERE endpoint = ?", endpoint)
	if err != nil {
		return fmt.Errorf("deleting subscription: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// List returns all subscriptions with pagination.
func (s *SQLite) List(ctx context.Context, limit, offset int) ([]*Record, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, endpoint, p256dh, auth, created_at, updated_at
		FROM subscriptions
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("querying subscriptions: %w", err)
	}
	defer rows.Close()
	return scanRecords(rows)
}

// Close closes the database connection.
func (s *SQLite) Close() error {
	return s.db.Close()
}

type scanner interface {
	Scan(dest ...interface{}) error
}

func scanRecord(row scanner) (*Record, error) {
	var (
		id        string
		userID    sql.NullString
		endpoint  string
		p256dh    string
		auth      string
		createdAt time.Time
		updatedAt time.Time
	)
	err := row.Scan(&id, &userID, &endpoint, &p256dh, &auth, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scanning row: %w", err)
	}
	return &Record{
		ID:        id,
		UserID:    userID.String,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
		Subscription: &webpush.Subscription{
			Endpoint: endpoint,
			Keys: webpush.Keys{
				P256dh: p256dh,
				Auth:   auth,
			},
		},
	}, nil
}

func scanRecords(rows *sql.Rows) ([]*Record, error) {
	var records []*Record
	for rows.Next() {
		record, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}
	return records, nil
}
