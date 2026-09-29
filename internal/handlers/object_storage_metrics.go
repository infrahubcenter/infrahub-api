package handlers

import (
	"net/http"
	"time"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/services"
)

const (
	defaultObjectStorageHistoryRange = 24 * time.Hour
	maxObjectStorageHistoryRange     = 30 * 24 * time.Hour
	// maxObjectStorageHistoryPoints bounds ListObjectStorageMetricsSince's
	// result set -- same order of magnitude as vm_monitoring.go's
	// defaultHistoryLimit (500), the one bounded range+limit history
	// endpoint that already exists in this codebase (the Database
	// equivalent, ListStandaloneDatabaseMetricsSince, has no row cap at
	// all -- there is nothing concrete there to mirror instead).
	maxObjectStorageHistoryPoints = 500
)

// objectStorageMetricsDTO is the exact response shape
// frontend/src/lib/api.ts's ObjectStorageMetrics type already expects
// (Step 17 Phase 2, shipped ahead of this backend work): every field a
// pointer + `omitempty` so an uncollected metric is truly ABSENT from the
// JSON, never a fabricated 0/false/"". Shared by both MetricsCurrent
// (used flat) and MetricsHistory (embedded per-point, with CapturedAt
// always present there).
type objectStorageMetricsDTO struct {
	ObjectCount      *int64   `json:"object_count,omitempty"`
	TotalSizeBytes   *int64   `json:"total_size_bytes,omitempty"`
	RequestsPerMin   *float64 `json:"requests_per_min,omitempty"`
	ErrorCount       *int32   `json:"error_count,omitempty"`
	BucketReachable  *bool    `json:"bucket_reachable,omitempty"`
	RequestLatencyMs *float64 `json:"request_latency_ms,omitempty"`
	CapturedAt       *string  `json:"captured_at,omitempty"`
}

// MetricsCurrent handles GET /api/object-storage/:id/metrics/current: the
// latest cached fast-metrics sample if present (never triggering a new
// connection on read), else the latest object_storage_metrics DB row,
// else every field absent. A storage that exists but was never monitored
// returns 200 with an all-fields-absent body, never a 404 -- the
// frontend's "No metrics collected yet" empty state relies on true field
// absence, not null/0/false.
func (h *ObjectStorageHandler) MetricsCurrent(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageMonitor)
	if !ok {
		return
	}
	var resp objectStorageMetricsDTO
	if entry, found := h.cache.Get(os.ID); found {
		resp = objectStorageMetricsDTOFromSample(entry.Snapshot, entry.CapturedAt)
	} else if row, err := h.store.GetLatestObjectStorageMetric(r.Context(), os.ID); err == nil {
		resp = objectStorageMetricsDTOFromRow(row)
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// MetricsHistory handles GET /api/object-storage/:id/metrics/history?from=&to=.
// An empty range (or a storage never monitored) returns {"points": []},
// never an error.
func (h *ObjectStorageHandler) MetricsHistory(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageMonitor)
	if !ok {
		return
	}
	from, to := parseObjectStorageHistoryRange(r)
	rows, err := h.store.ListObjectStorageMetricsSince(r.Context(), generated.ListObjectStorageMetricsSinceParams{
		ObjectStorageID: os.ID, CapturedAt: pgutil.Timestamptz(from), CapturedAt_2: pgutil.Timestamptz(to), Limit: maxObjectStorageHistoryPoints,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load metrics history")
		return
	}
	// rows come back newest-first (DESC + LIMIT, so a range holding more
	// samples than the cap still keeps the most recent ones); reverse into
	// chronological order for the frontend's line chart.
	points := make([]objectStorageMetricsDTO, len(rows))
	for i, row := range rows {
		points[len(rows)-1-i] = objectStorageMetricsDTOFromRow(row)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"points": points})
}

func objectStorageMetricsDTOFromRow(row generated.ObjectStorageMetric) objectStorageMetricsDTO {
	dto := objectStorageMetricsDTO{
		ObjectCount: pgutil.Int8Ptr(row.ObjectCount), TotalSizeBytes: pgutil.Int8Ptr(row.TotalSizeBytes),
		ErrorCount: pgutil.Int4Ptr(row.ErrorCount), BucketReachable: pgutil.BoolPtr(row.Reachable),
		RequestLatencyMs: pgutil.Float8Ptr(row.LatencyMs),
	}
	if row.RequestCount.Valid {
		rpm := float64(row.RequestCount.Int64)
		dto.RequestsPerMin = &rpm
	}
	if row.CapturedAt.Valid {
		captured := row.CapturedAt.Time.Format(time.RFC3339)
		dto.CapturedAt = &captured
	}
	return dto
}

func objectStorageMetricsDTOFromSample(sample services.ObjectStorageMetricsSample, capturedAt time.Time) objectStorageMetricsDTO {
	dto := objectStorageMetricsDTO{
		BucketReachable: sample.BucketReachable, RequestLatencyMs: sample.RequestLatencyMs,
		ObjectCount: sample.ObjectCount, TotalSizeBytes: sample.TotalSizeBytes, RequestsPerMin: sample.RequestsPerMin,
	}
	if sample.ErrorCount != nil {
		ec := int32(*sample.ErrorCount)
		dto.ErrorCount = &ec
	}
	captured := capturedAt.Format(time.RFC3339)
	dto.CapturedAt = &captured
	return dto
}

// parseObjectStorageHistoryRange parses ?from=&to= (RFC3339), defaulting
// to the last 24h and clamped to 30 days -- same bounding discipline as
// parseDatabaseHistoryRange (database_metrics.go).
func parseObjectStorageHistoryRange(r *http.Request) (time.Time, time.Time) {
	now := time.Now()
	from := now.Add(-defaultObjectStorageHistoryRange)
	to := now
	if v := r.URL.Query().Get("from"); v != "" {
		if parsed, err := time.Parse(time.RFC3339, v); err == nil {
			from = parsed
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if parsed, err := time.Parse(time.RFC3339, v); err == nil {
			to = parsed
		}
	}
	if to.Before(from) {
		to = from
	}
	if to.Sub(from) > maxObjectStorageHistoryRange {
		from = to.Add(-maxObjectStorageHistoryRange)
	}
	return from, to
}
