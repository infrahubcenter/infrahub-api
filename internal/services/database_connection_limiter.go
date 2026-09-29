package services

import "context"

// DatabaseConnectionLimiter bounds the number of simultaneous monitoring
// connections this application ever opens to target databases (spec
// #133/#134): "database monitoring connection pools must be small... do
// not consume the connection pool needed by the application." Shared by
// both DatabaseMetricsService (fast cycle) and DatabaseDeepMetricsService
// (deep cycle) so their worker pools' combined concurrency is still
// capped by one real number, DATABASE_MONITOR_MAX_CONNECTIONS -- not just
// each scheduler's own independent worker count.
type DatabaseConnectionLimiter struct {
	slots chan struct{}
}

// NewDatabaseConnectionLimiter creates a limiter allowing at most max
// concurrent acquisitions. max < 1 is treated as 1 (never unlimited).
func NewDatabaseConnectionLimiter(max int32) *DatabaseConnectionLimiter {
	if max < 1 {
		max = 1
	}
	return &DatabaseConnectionLimiter{slots: make(chan struct{}, max)}
}

// Acquire blocks until a slot is free or ctx is cancelled.
func (l *DatabaseConnectionLimiter) Acquire(ctx context.Context) error {
	select {
	case l.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release frees the slot acquired by a matching Acquire call.
func (l *DatabaseConnectionLimiter) Release() {
	select {
	case <-l.slots:
	default:
	}
}
