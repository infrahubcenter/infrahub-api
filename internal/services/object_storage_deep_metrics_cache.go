package services

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// ObjectStorageDeepMetricsSample is what the deep-metrics cache carries --
// mirrors DeepMetricsSample's "not the raw generated row" discipline, plus
// object storage's own bucket-count/size fields (deliberately duplicated
// here rather than read back from ObjectStorageMetricsCache, so a reader
// of this cache gets one self-contained, point-in-time-consistent
// snapshot). Every status field defaults to "UNKNOWN"/nil exactly as
// ObjectStorageDeepMetricsResult does -- never a fabricated value.
type ObjectStorageDeepMetricsSample struct {
	VersioningStatus  string
	EncryptionStatus  string
	PublicAccess      string
	ObjectLockStatus  string
	ObjectCount       *int64
	TotalSizeBytes    *int64
	GrowthBytesPerDay *float64
	GrowthPercent     *float64
	ErrorRatePercent  *float64
	Partial           bool
	MetricsStatus     string // COMPLETE | PARTIAL | FAILED
}

// ObjectStorageDeepMetricsCacheEntry is the latest known deep sample for
// one object storage.
type ObjectStorageDeepMetricsCacheEntry struct {
	Snapshot   ObjectStorageDeepMetricsSample
	CapturedAt time.Time
}

// ObjectStorageDeepMetricsCache is the shared, single-collector-many-
// viewers cache for deep metrics, keyed by object storage ID, written only
// by ObjectStorageDeepMetricsService -- mirrors DatabaseDeepMetricsCache's
// shape exactly.
type ObjectStorageDeepMetricsCache struct {
	mu      sync.RWMutex
	entries map[uuid.UUID]ObjectStorageDeepMetricsCacheEntry
}

// NewObjectStorageDeepMetricsCache creates an empty ObjectStorageDeepMetricsCache.
func NewObjectStorageDeepMetricsCache() *ObjectStorageDeepMetricsCache {
	return &ObjectStorageDeepMetricsCache{entries: make(map[uuid.UUID]ObjectStorageDeepMetricsCacheEntry)}
}

// Set stores the latest deep sample for an object storage.
func (c *ObjectStorageDeepMetricsCache) Set(objectStorageID uuid.UUID, sample ObjectStorageDeepMetricsSample, capturedAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[objectStorageID] = ObjectStorageDeepMetricsCacheEntry{Snapshot: sample, CapturedAt: capturedAt}
}

// Get returns the latest cached deep sample, if any has ever been
// collected.
func (c *ObjectStorageDeepMetricsCache) Get(objectStorageID uuid.UUID) (ObjectStorageDeepMetricsCacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[objectStorageID]
	return entry, ok
}
