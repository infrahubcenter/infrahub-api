package services

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// DockerMetricsCacheEntry is one container's latest known stats sample,
// plus when it was captured -- lets a reader (the WebSocket stream, the
// "current metrics" REST endpoint) judge staleness (spec §83) without a
// second SSH round trip.
type DockerMetricsCacheEntry struct {
	Stats      ContainerStats
	CapturedAt time.Time
}

// DockerMetricsCache is a shared, in-memory, thread-safe cache of the
// most recent metrics sample per container, keyed by the container's DB
// row ID (which already uniquely identifies one container on one VM --
// no separate vm_id half of the key is needed). DockerMetricsScheduler is
// its only writer, populated once per DOCKER_METRICS_INTERVAL cycle; the
// live WebSocket stream and REST "current metrics" endpoints are its only
// readers. Neither reader path ever triggers a new SSH command -- this is
// exactly what makes it safe for multiple browser viewers to watch the
// same container without opening multiple SSH connections or duplicating
// the collector (spec §49-54).
type DockerMetricsCache struct {
	mu      sync.RWMutex
	entries map[uuid.UUID]DockerMetricsCacheEntry
}

// NewDockerMetricsCache creates an empty DockerMetricsCache.
func NewDockerMetricsCache() *DockerMetricsCache {
	return &DockerMetricsCache{entries: make(map[uuid.UUID]DockerMetricsCacheEntry)}
}

// Set stores containerDBID's latest sample, overwriting whatever was
// cached before.
func (c *DockerMetricsCache) Set(containerDBID uuid.UUID, stats ContainerStats, capturedAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[containerDBID] = DockerMetricsCacheEntry{Stats: stats, CapturedAt: capturedAt}
}

// Get returns containerDBID's latest cached sample, if any -- false when
// nothing has been collected for this container yet (a container that
// only just started running, before the next metrics cycle).
func (c *DockerMetricsCache) Get(containerDBID uuid.UUID) (DockerMetricsCacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[containerDBID]
	return entry, ok
}
