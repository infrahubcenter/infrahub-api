package services

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// DeepMetricsSample is what the deep-metrics cache/performance API/stream
// carries -- mirrors DatabaseMetricsSample's "not the raw generated row"
// discipline exactly, so the handler layer never needs to know about
// column shapes.
type DeepMetricsSample struct {
	CacheHitRatio     *float64
	Locks             LockMetrics
	Replication       ReplicationDetail
	LatencyP50Ms      *float64
	LatencyP95Ms      *float64
	LatencyP99Ms      *float64
	GrowthBytesPerDay *float64
	MetricsStatus     string
	Sessions          []SessionInfo
	TopQueries        []QueryMetric
}

// DatabaseDeepMetricsCache is the shared, single-collector-many-viewers
// cache for deep metrics, keyed by database ID, written only by
// DatabaseDeepMetricsScheduler.
type DatabaseDeepMetricsCache struct {
	mu      sync.RWMutex
	entries map[uuid.UUID]DeepMetricsCacheEntry
}

// DeepMetricsCacheEntry is the latest known deep sample for one database.
type DeepMetricsCacheEntry struct {
	Snapshot   DeepMetricsSample
	CapturedAt time.Time
}

// NewDatabaseDeepMetricsCache creates an empty DatabaseDeepMetricsCache.
func NewDatabaseDeepMetricsCache() *DatabaseDeepMetricsCache {
	return &DatabaseDeepMetricsCache{entries: make(map[uuid.UUID]DeepMetricsCacheEntry)}
}

// Set stores the latest deep sample for a database.
func (c *DatabaseDeepMetricsCache) Set(databaseID uuid.UUID, sample DeepMetricsSample, capturedAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[databaseID] = DeepMetricsCacheEntry{Snapshot: sample, CapturedAt: capturedAt}
}

// Get returns the latest cached deep sample, if any has ever been
// collected.
func (c *DatabaseDeepMetricsCache) Get(databaseID uuid.UUID) (DeepMetricsCacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[databaseID]
	return entry, ok
}
