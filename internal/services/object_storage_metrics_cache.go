package services

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// ObjectStorageMetricsSample is what the cache carries -- deliberately
// pointer-typed throughout (never a fabricated zero/false for a metric
// that was not actually collected), mirrors DatabaseMetricsSample's role
// scoped to object storage's fast cycle. BucketReachable/RequestLatencyMs/
// ErrorCount come from a HeadBucket probe every fast cycle;
// ObjectCount/TotalSizeBytes/RequestsPerMin stay nil until a later phase's
// deep/bucket-scan cycle starts populating object_storage_metrics's wider
// columns -- included here now so ObjectStorageMetricsService.CollectOne
// and this cache need no shape change once that phase ships.
type ObjectStorageMetricsSample struct {
	BucketReachable  *bool
	RequestLatencyMs *float64
	ErrorCount       *int64
	ObjectCount      *int64
	TotalSizeBytes   *int64
	RequestsPerMin   *float64
	HealthStatus     HealthStatus
	MetricsStatus    string // COMPLETE | PARTIAL | FAILED
}

// ObjectStorageMetricsCacheEntry is the latest known sample for one
// object storage.
type ObjectStorageMetricsCacheEntry struct {
	Snapshot   ObjectStorageMetricsSample
	CapturedAt time.Time
}

// ObjectStorageMetricsCache is the shared, single-collector-many-viewers
// cache (mirrors DatabaseMetricsCache): keyed by object storage ID,
// written only by ObjectStorageMetricsService, read by the
// GET .../metrics/current endpoint and the object storage list/detail
// DTOs -- never triggers a new connection on read.
type ObjectStorageMetricsCache struct {
	mu      sync.RWMutex
	entries map[uuid.UUID]ObjectStorageMetricsCacheEntry
}

// NewObjectStorageMetricsCache creates an empty ObjectStorageMetricsCache.
func NewObjectStorageMetricsCache() *ObjectStorageMetricsCache {
	return &ObjectStorageMetricsCache{entries: make(map[uuid.UUID]ObjectStorageMetricsCacheEntry)}
}

// Set stores the latest sample for an object storage.
func (c *ObjectStorageMetricsCache) Set(objectStorageID uuid.UUID, sample ObjectStorageMetricsSample, capturedAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[objectStorageID] = ObjectStorageMetricsCacheEntry{Snapshot: sample, CapturedAt: capturedAt}
}

// Get returns the latest cached sample, if any has ever been collected.
func (c *ObjectStorageMetricsCache) Get(objectStorageID uuid.UUID) (ObjectStorageMetricsCacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[objectStorageID]
	return entry, ok
}

// MergeBucketMetrics updates just the ObjectCount/TotalSizeBytes/
// RequestsPerMin fields of the current cache entry (if one exists),
// leaving every other field -- BucketReachable/RequestLatencyMs/ErrorCount/
// HealthStatus/MetricsStatus, and the entry's own CapturedAt -- untouched.
// Written by ObjectStorageDeepMetricsService (Step 17 Phase 3) after a
// deep cycle observes a fresh object count/size (via CloudWatch or the
// bounded-listing fallback): the much-less-frequent deep cycle's result
// must never overwrite the fast cycle's independently-collected
// reachability sample, or vice versa -- each cycle only ever updates the
// fields it actually measured. A no-op if the fast cycle has never run yet
// (nothing to merge into); the next fast cycle tick will itself preserve
// these bucket-metric fields rather than resetting them to nil (see
// ObjectStorageMetricsService.CollectOne).
func (c *ObjectStorageMetricsCache) MergeBucketMetrics(objectStorageID uuid.UUID, objectCount, totalSizeBytes *int64, requestsPerMin *float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[objectStorageID]
	if !ok {
		return
	}
	entry.Snapshot.ObjectCount = objectCount
	entry.Snapshot.TotalSizeBytes = totalSizeBytes
	entry.Snapshot.RequestsPerMin = requestsPerMin
	c.entries[objectStorageID] = entry
}
