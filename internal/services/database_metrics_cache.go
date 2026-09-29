package services

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// DatabaseMetricsSample is what the cache/WebSocket stream carries --
// deliberately not the raw generated row, so the handler layer never
// needs to know about DB column shapes.
type DatabaseMetricsSample struct {
	Common        CommonMetrics
	Details       map[string]any
	HealthStatus  HealthStatus
	MetricsStatus string // COMPLETE | PARTIAL | FAILED
}

// DatabaseMetricsCacheEntry is the latest known sample for one database.
type DatabaseMetricsCacheEntry struct {
	Snapshot   DatabaseMetricsSample
	CapturedAt time.Time
}

// DatabaseMetricsCache is the shared, single-collector-many-viewers
// cache (spec §46): keyed by database ID, written only by
// DatabaseMetricsScheduler, read by REST "current" endpoints and the
// WebSocket stream -- never triggers a new connection on read.
type DatabaseMetricsCache struct {
	mu      sync.RWMutex
	entries map[uuid.UUID]DatabaseMetricsCacheEntry
}

// NewDatabaseMetricsCache creates an empty DatabaseMetricsCache.
func NewDatabaseMetricsCache() *DatabaseMetricsCache {
	return &DatabaseMetricsCache{entries: make(map[uuid.UUID]DatabaseMetricsCacheEntry)}
}

// Set stores the latest sample for a database.
func (c *DatabaseMetricsCache) Set(databaseID uuid.UUID, sample DatabaseMetricsSample, capturedAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[databaseID] = DatabaseMetricsCacheEntry{Snapshot: sample, CapturedAt: capturedAt}
}

// Get returns the latest cached sample, if any has ever been collected.
func (c *DatabaseMetricsCache) Get(databaseID uuid.UUID) (DatabaseMetricsCacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[databaseID]
	return entry, ok
}
