package keys

import (
	"context"
	"encoding/base64"
)

// SubscriptionCounter is an interface for counting subscriptions by VAPID key.
// This is typically implemented by a storage backend.
type SubscriptionCounter interface {
	// CountByVAPIDKey returns the number of subscriptions for a specific VAPID key.
	CountByVAPIDKey(ctx context.Context, vapidKey string) (int, error)
}

// RemoveUnusedKeysResult contains the result of a RemoveUnusedKeys operation.
type RemoveUnusedKeysResult struct {
	// RemovedKeys contains the base64-encoded public keys that were removed.
	RemovedKeys []string
	// RetainedKeys contains the base64-encoded public keys that were retained
	// because they have associated subscriptions.
	RetainedKeys []string
}

// RemoveUnusedKeys removes previous keys from the rotating signer that have no
// associated subscriptions in the given storage. The current key is never removed.
//
// This is useful for cleaning up old keys after all subscriptions have been
// migrated to the current key.
func (r *RotatingSigner) RemoveUnusedKeys(ctx context.Context, counter SubscriptionCounter) (*RemoveUnusedKeysResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := &RemoveUnusedKeysResult{}
	var retained []Signer

	for _, signer := range r.previous {
		keyB64 := base64.RawURLEncoding.EncodeToString(signer.PublicKey())
		count, err := counter.CountByVAPIDKey(ctx, keyB64)
		if err != nil {
			return nil, err
		}

		if count > 0 {
			retained = append(retained, signer)
			result.RetainedKeys = append(result.RetainedKeys, keyB64)
		} else {
			result.RemovedKeys = append(result.RemovedKeys, keyB64)
		}
	}

	r.previous = retained
	return result, nil
}

// RemoveUnusedKeys removes previous keys from the rotating KMS signer that have no
// associated subscriptions in the given storage. The current key is never removed.
//
// This is useful for cleaning up old keys after all subscriptions have been
// migrated to the current key.
func (r *RotatingKMSSigner) RemoveUnusedKeys(ctx context.Context, counter SubscriptionCounter) (*RemoveUnusedKeysResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := &RemoveUnusedKeysResult{}
	var retained []*kmsKeyVersion

	for _, kv := range r.previous {
		keyB64 := base64.RawURLEncoding.EncodeToString(kv.publicKey)
		count, err := counter.CountByVAPIDKey(ctx, keyB64)
		if err != nil {
			return nil, err
		}

		if count > 0 {
			retained = append(retained, kv)
			result.RetainedKeys = append(result.RetainedKeys, keyB64)
		} else {
			result.RemovedKeys = append(result.RemovedKeys, keyB64)
		}
	}

	r.previous = retained
	return result, nil
}
