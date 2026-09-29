package services

import "context"

// ObjectStorageConnectionLimiter bounds the number of simultaneous
// monitoring connections this application ever opens to target object
// storage buckets -- same rationale as DatabaseConnectionLimiter
// (spec #133/#134 for databases, mirrored here): object storage monitoring
// must never be allowed to open an unbounded number of concurrent S3
// client connections just because a scheduler's worker count is high.
// Object storage is its own small, plain chan-struct{}-backed semaphore
// rather than a genericized shared type with DatabaseConnectionLimiter --
// the two resource kinds have independent OBJECT_STORAGE_MONITOR_MAX_CONNECTIONS/
// DATABASE_MONITOR_MAX_CONNECTIONS caps, and unifying them would be a
// larger refactor than this phase calls for.
type ObjectStorageConnectionLimiter struct {
	slots chan struct{}
}

// NewObjectStorageConnectionLimiter creates a limiter allowing at most max
// concurrent acquisitions. max < 1 is treated as 1 (never unlimited).
func NewObjectStorageConnectionLimiter(max int32) *ObjectStorageConnectionLimiter {
	if max < 1 {
		max = 1
	}
	return &ObjectStorageConnectionLimiter{slots: make(chan struct{}, max)}
}

// Acquire blocks until a slot is free or ctx is cancelled.
func (l *ObjectStorageConnectionLimiter) Acquire(ctx context.Context) error {
	select {
	case l.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release frees the slot acquired by a matching Acquire call.
func (l *ObjectStorageConnectionLimiter) Release() {
	select {
	case <-l.slots:
	default:
	}
}
