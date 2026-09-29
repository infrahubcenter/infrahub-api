package handlers

import (
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/services"
)

type databaseLockMetricsDTO struct {
	Waiting *int64 `json:"waiting,omitempty"`
	Blocked *int64 `json:"blocked,omitempty"`
}

type databaseReplicationDTO struct {
	Status       string   `json:"status"`
	LagSeconds   *float64 `json:"lag_seconds,omitempty"`
	ReplicaCount *int64   `json:"replica_count,omitempty"`
}

type databaseSessionDTO struct {
	PID             int64    `json:"pid"`
	Database        string   `json:"database,omitempty"`
	User            string   `json:"user,omitempty"`
	DurationSeconds int64    `json:"duration_seconds"`
	State           string   `json:"state,omitempty"`
	WaitEventType   string   `json:"wait_event_type,omitempty"`
	WaitEvent       string   `json:"wait_event,omitempty"`
	ApplicationName string   `json:"application_name,omitempty"`
	BlockingPIDs    []string `json:"blocking_pids,omitempty"`
}

type databaseQueryDTO struct {
	Fingerprint    string   `json:"fingerprint"`
	Calls          *int64   `json:"calls,omitempty"`
	TotalTimeMs    *float64 `json:"total_time_ms,omitempty"`
	AvgTimeMs      *float64 `json:"avg_time_ms,omitempty"`
	Rows           *int64   `json:"rows,omitempty"`
	BlocksRead     *int64   `json:"blocks_read,omitempty"`
	BlocksHit      *int64   `json:"blocks_hit,omitempty"`
	DatabaseName   string   `json:"database_name,omitempty"`
	DatabaseUser   string   `json:"database_user,omitempty"`
	NormalizedText string   `json:"normalized_text,omitempty"`
	CapturedAt     string   `json:"captured_at,omitempty"`
}

type databasePerformanceCurrentResponse struct {
	CapturedAt        *string                 `json:"captured_at,omitempty"`
	MetricsStatus     string                  `json:"metrics_status,omitempty"`
	CacheHitRatio     *float64                `json:"cache_hit_ratio,omitempty"`
	Locks             *databaseLockMetricsDTO `json:"locks,omitempty"`
	Replication       *databaseReplicationDTO `json:"replication,omitempty"`
	LatencyP50Ms      *float64                `json:"latency_p50_ms,omitempty"`
	LatencyP95Ms      *float64                `json:"latency_p95_ms,omitempty"`
	LatencyP99Ms      *float64                `json:"latency_p99_ms,omitempty"`
	GrowthBytesPerDay *float64                `json:"growth_bytes_per_day,omitempty"`
	Sessions          []databaseSessionDTO    `json:"sessions,omitempty"`
	TopQueries        []databaseQueryDTO      `json:"top_queries,omitempty"`
}

// deepSampleToDTO renders a DeepMetricsSample. includeQueryText gates
// whether TopQueries carries NormalizedText -- Admin/database.query_details
// only (spec §64); every other caller gets fingerprint + aggregated stats
// with no query text at all, regardless of what DATABASE_QUERY_TEXT_CAPTURE
// stored.
func deepSampleToDTO(entry services.DeepMetricsCacheEntry, includeQueryText bool) databasePerformanceCurrentResponse {
	formatted := entry.CapturedAt.Format(time.RFC3339)
	resp := databasePerformanceCurrentResponse{
		CapturedAt: &formatted, MetricsStatus: entry.Snapshot.MetricsStatus, CacheHitRatio: entry.Snapshot.CacheHitRatio,
		Locks:             &databaseLockMetricsDTO{Waiting: entry.Snapshot.Locks.Waiting, Blocked: entry.Snapshot.Locks.Blocked},
		Replication:       &databaseReplicationDTO{Status: entry.Snapshot.Replication.Status, LagSeconds: entry.Snapshot.Replication.LagSeconds, ReplicaCount: entry.Snapshot.Replication.ReplicaCount},
		LatencyP50Ms:      entry.Snapshot.LatencyP50Ms,
		LatencyP95Ms:      entry.Snapshot.LatencyP95Ms,
		LatencyP99Ms:      entry.Snapshot.LatencyP99Ms,
		GrowthBytesPerDay: entry.Snapshot.GrowthBytesPerDay,
	}
	for _, s := range entry.Snapshot.Sessions {
		resp.Sessions = append(resp.Sessions, databaseSessionDTO{
			PID: s.PID, Database: s.Database, User: s.User, DurationSeconds: s.DurationSeconds, State: s.State,
			WaitEventType: s.WaitEventType, WaitEvent: s.WaitEvent, ApplicationName: s.ApplicationName, BlockingPIDs: s.BlockingPIDs,
		})
	}
	for _, q := range entry.Snapshot.TopQueries {
		dto := databaseQueryDTO{
			Fingerprint: q.Fingerprint, Calls: q.Calls, TotalTimeMs: q.TotalTimeMs, AvgTimeMs: q.AvgTimeMs, Rows: q.Rows,
			BlocksRead: q.BlocksRead, BlocksHit: q.BlocksHit, DatabaseName: q.DatabaseName, DatabaseUser: q.DatabaseUser,
		}
		if includeQueryText {
			dto.NormalizedText = q.NormalizedText
		}
		resp.TopQueries = append(resp.TopQueries, dto)
	}
	return resp
}

// Performance handles GET /api/databases/:id/performance: the latest
// cached deep-metrics sample (spec §43's combined performance view).
func (h *DatabaseHandler) Performance(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabasePerformance)
	if !ok {
		return
	}
	entry, found := h.deepCache.Get(db.ID)
	if !found {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "NO_DATA"})
		return
	}
	includeQueryText, _ := h.authz.CanAccessDatabase(r.Context(), mustUser(r), db.ResourceID, services.PermDatabaseQueryDetails)
	httpx.WriteJSON(w, http.StatusOK, deepSampleToDTO(entry, includeQueryText))
}

// PerformanceHistory handles GET /api/databases/:id/performance/history?from=&to=.
func (h *DatabaseHandler) PerformanceHistory(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabasePerformance)
	if !ok {
		return
	}
	from, to := parseDatabaseHistoryRange(r, defaultDatabaseHistoryRange, maxDatabaseHistoryRange)
	rows, err := h.store.ListStandaloneDatabaseDeepMetricsSince(r.Context(), generated.ListStandaloneDatabaseDeepMetricsSinceParams{DatabaseID: db.ID, CapturedAt: pgutil.Timestamptz(from)})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load performance history")
		return
	}
	type point struct {
		CapturedAt        string   `json:"captured_at"`
		MetricsStatus     string   `json:"metrics_status,omitempty"`
		CacheHitRatio     *float64 `json:"cache_hit_ratio,omitempty"`
		LocksWaiting      *int32   `json:"locks_waiting,omitempty"`
		LocksBlocked      *int32   `json:"locks_blocked,omitempty"`
		ReplicationLagSec *float64 `json:"replication_lag_seconds,omitempty"`
		LatencyP95Ms      *float64 `json:"latency_p95_ms,omitempty"`
		GrowthBytesPerDay *float64 `json:"growth_bytes_per_day,omitempty"`
	}
	points := make([]point, 0, len(rows))
	for _, row := range rows {
		if row.CapturedAt.Time.After(to) {
			continue
		}
		points = append(points, point{
			CapturedAt: row.CapturedAt.Time.Format(time.RFC3339), MetricsStatus: row.MetricsStatus, CacheHitRatio: pgutil.Float8Ptr(row.CacheHitRatio),
			LocksWaiting: pgutil.Int4Ptr(row.LocksWaiting), LocksBlocked: pgutil.Int4Ptr(row.LocksBlocked),
			ReplicationLagSec: pgutil.Float8Ptr(row.ReplicationLagSeconds), LatencyP95Ms: pgutil.Float8Ptr(row.LatencyP95Ms),
			GrowthBytesPerDay: pgutil.Float8Ptr(row.GrowthBytesPerDay),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"from": from.Format(time.RFC3339), "to": to.Format(time.RFC3339), "points": points})
}

// PerformanceStream handles GET /api/databases/:id/performance/stream: a
// WebSocket pushing the latest cached deep-metrics sample once per
// DATABASE_DEEP_METRICS_STREAM_INTERVAL -- read-only, cache-backed,
// mirrors MetricsStream exactly.
func (h *DatabaseHandler) PerformanceStream(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabasePerformance)
	if !ok {
		return
	}
	includeQueryText, _ := h.authz.CanAccessDatabase(r.Context(), mustUser(r), db.ResourceID, services.PermDatabaseQueryDetails)

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "" || origin == h.frontendOrigin
		},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	ctx := r.Context()
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	interval := h.streamInterval
	if interval <= 0 {
		interval = 60 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	push := func() bool {
		entry, found := h.deepCache.Get(db.ID)
		if !found {
			return conn.WriteJSON(map[string]any{"type": "waiting", "reason": "no performance metrics collected yet for this database"}) == nil
		}
		return conn.WriteJSON(deepSampleToDTO(entry, includeQueryText)) == nil
	}
	if !push() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-closed:
			return
		case <-ticker.C:
			if !push() {
				return
			}
		}
	}
}

// Queries handles GET /api/databases/:id/queries: the latest ranked
// query list, from the deep cache -- query text gated to
// database.query_details/Admin (spec §64).
func (h *DatabaseHandler) Queries(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabasePerformance)
	if !ok {
		return
	}
	includeQueryText, _ := h.authz.CanAccessDatabase(r.Context(), mustUser(r), db.ResourceID, services.PermDatabaseQueryDetails)

	rows, err := h.store.ListLatestStandaloneDatabaseQueryMetrics(r.Context(), db.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load query metrics")
		return
	}
	items := make([]databaseQueryDTO, 0, len(rows))
	for _, row := range rows {
		dto := databaseQueryDTO{
			Fingerprint: row.QueryFingerprint, Calls: pgutil.Int8Ptr(row.Calls), TotalTimeMs: pgutil.Float8Ptr(row.TotalTimeMs),
			AvgTimeMs: pgutil.Float8Ptr(row.AvgTimeMs), Rows: pgutil.Int8Ptr(row.Rows), BlocksRead: pgutil.Int8Ptr(row.BlocksRead),
			BlocksHit: pgutil.Int8Ptr(row.BlocksHit), DatabaseName: pgutil.TextOrEmpty(row.DatabaseName), DatabaseUser: pgutil.TextOrEmpty(row.DatabaseUser),
			CapturedAt: row.CapturedAt.Time.Format(time.RFC3339),
		}
		if includeQueryText {
			dto.NormalizedText = pgutil.TextOrEmpty(row.NormalizedText)
		}
		items = append(items, dto)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"queries": items})
}

// QueryDetail handles GET /api/databases/:id/queries/:fingerprint: one
// query's latest stats plus its captured trend history.
func (h *DatabaseHandler) QueryDetail(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabasePerformance)
	if !ok {
		return
	}
	includeQueryText, _ := h.authz.CanAccessDatabase(r.Context(), mustUser(r), db.ResourceID, services.PermDatabaseQueryDetails)
	fingerprint := r.PathValue("fingerprint")

	latest, err := h.store.GetLatestStandaloneDatabaseQueryMetric(r.Context(), generated.GetLatestStandaloneDatabaseQueryMetricParams{DatabaseID: db.ID, QueryFingerprint: fingerprint})
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "query not found")
		return
	}
	from, to := parseDatabaseHistoryRange(r, defaultDatabaseHistoryRange, maxDatabaseHistoryRange)
	history, err := h.store.ListStandaloneDatabaseQueryMetricsSince(r.Context(), generated.ListStandaloneDatabaseQueryMetricsSinceParams{DatabaseID: db.ID, CapturedAt: pgutil.Timestamptz(from)})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load query history")
		return
	}

	firstSeen := ""
	if first, err := h.store.GetFirstStandaloneDatabaseQueryMetric(r.Context(), generated.GetFirstStandaloneDatabaseQueryMetricParams{DatabaseID: db.ID, QueryFingerprint: fingerprint}); err == nil {
		firstSeen = first.CapturedAt.Time.Format(time.RFC3339)
	}

	dto := databaseQueryDTO{
		Fingerprint: latest.QueryFingerprint, Calls: pgutil.Int8Ptr(latest.Calls), TotalTimeMs: pgutil.Float8Ptr(latest.TotalTimeMs),
		AvgTimeMs: pgutil.Float8Ptr(latest.AvgTimeMs), Rows: pgutil.Int8Ptr(latest.Rows), BlocksRead: pgutil.Int8Ptr(latest.BlocksRead),
		BlocksHit: pgutil.Int8Ptr(latest.BlocksHit), DatabaseName: pgutil.TextOrEmpty(latest.DatabaseName), DatabaseUser: pgutil.TextOrEmpty(latest.DatabaseUser),
		CapturedAt: latest.CapturedAt.Time.Format(time.RFC3339),
	}
	if includeQueryText {
		dto.NormalizedText = pgutil.TextOrEmpty(latest.NormalizedText)
	}

	type historyPoint struct {
		CapturedAt  string   `json:"captured_at"`
		Calls       *int64   `json:"calls,omitempty"`
		TotalTimeMs *float64 `json:"total_time_ms,omitempty"`
		AvgTimeMs   *float64 `json:"avg_time_ms,omitempty"`
	}
	points := make([]historyPoint, 0, len(history))
	for _, row := range history {
		if row.CapturedAt.Time.After(to) {
			continue
		}
		points = append(points, historyPoint{
			CapturedAt: row.CapturedAt.Time.Format(time.RFC3339), Calls: pgutil.Int8Ptr(row.Calls),
			TotalTimeMs: pgutil.Float8Ptr(row.TotalTimeMs), AvgTimeMs: pgutil.Float8Ptr(row.AvgTimeMs),
		})
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"query": dto, "first_seen_at": firstSeen, "history": points})
}

// Connections handles GET /api/databases/:id/connections: the latest
// cached deep-cycle session snapshot (spec §33's non-sensitive session
// facts -- never a query-text field, by construction of SessionInfo).
func (h *DatabaseHandler) Connections(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabasePerformance)
	if !ok {
		return
	}
	entry, found := h.deepCache.Get(db.ID)
	if !found {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "NO_DATA"})
		return
	}
	resp := deepSampleToDTO(entry, false)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"captured_at": resp.CapturedAt, "sessions": resp.Sessions})
}

// Locks handles GET /api/databases/:id/locks: the latest cached
// lock-contention counts.
func (h *DatabaseHandler) Locks(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabasePerformance)
	if !ok {
		return
	}
	entry, found := h.deepCache.Get(db.ID)
	if !found {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "NO_DATA"})
		return
	}
	resp := deepSampleToDTO(entry, false)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"captured_at": resp.CapturedAt, "locks": resp.Locks, "sessions": resp.Sessions})
}

// Replication handles GET /api/databases/:id/replication: the latest
// cached replication status/lag/replica count.
func (h *DatabaseHandler) Replication(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabasePerformance)
	if !ok {
		return
	}
	entry, found := h.deepCache.Get(db.ID)
	if !found {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "NO_DATA"})
		return
	}
	resp := deepSampleToDTO(entry, false)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"captured_at": resp.CapturedAt, "replication": resp.Replication})
}

// Storage handles GET /api/databases/:id/storage: the latest known size
// plus the cached growth-rate estimate.
func (h *DatabaseHandler) Storage(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabasePerformance)
	if !ok {
		return
	}
	var sizeBytes *int64
	var capturedAt *string
	if entry, found := h.cache.Get(db.ID); found {
		sizeBytes = entry.Snapshot.Common.DatabaseSizeBytes
		formatted := entry.CapturedAt.Format(time.RFC3339)
		capturedAt = &formatted
	}
	var growthBytesPerDay *float64
	if entry, found := h.deepCache.Get(db.ID); found {
		growthBytesPerDay = entry.Snapshot.GrowthBytesPerDay
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"captured_at": capturedAt, "database_size_bytes": sizeBytes, "growth_bytes_per_day": growthBytesPerDay,
	})
}

// StorageHistory handles GET /api/databases/:id/storage/history?from=&to=:
// the database's size-over-time trend.
func (h *DatabaseHandler) StorageHistory(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabasePerformance)
	if !ok {
		return
	}
	from, to := parseDatabaseHistoryRange(r, defaultDatabaseHistoryRange, maxDatabaseHistoryRange)
	rows, err := h.store.GetStandaloneDatabaseSizeHistorySince(r.Context(), generated.GetStandaloneDatabaseSizeHistorySinceParams{DatabaseID: db.ID, CapturedAt: pgutil.Timestamptz(from)})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load storage history")
		return
	}
	type point struct {
		CapturedAt        string `json:"captured_at"`
		DatabaseSizeBytes *int64 `json:"database_size_bytes,omitempty"`
	}
	points := make([]point, 0, len(rows))
	for _, row := range rows {
		if row.CapturedAt.Time.After(to) {
			continue
		}
		points = append(points, point{CapturedAt: row.CapturedAt.Time.Format(time.RFC3339), DatabaseSizeBytes: pgutil.Int8Ptr(row.DatabaseSizeBytes)})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"from": from.Format(time.RFC3339), "to": to.Format(time.RFC3339), "points": points})
}

// GlobalPerformanceOverview handles GET /api/databases/performance: a
// cross-database health/performance summary scoped to the caller's
// authorized databases (spec §43's "global performance dashboard"),
// mirroring List's scoping exactly.
func (h *DatabaseHandler) GlobalPerformanceOverview(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var resourceIDs []uuid.UUID
	if !user.IsAdmin() {
		access, err := h.authz.GetUserDatabaseAccess(r.Context(), user)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
			return
		}
		resourceIDs = make([]uuid.UUID, 0, len(access))
		for _, a := range access {
			if slices.Contains(a.Permissions, services.PermDatabasePerformance) {
				resourceIDs = append(resourceIDs, a.ResourceID)
			}
		}
	}
	rows, err := h.store.ListStandaloneDatabasesForDashboard(r.Context(), resourceIDs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load databases")
		return
	}
	items := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		entry := map[string]any{
			"id": row.ID.String(), "name": pgutil.TextOrEmpty(row.ResourceName), "workspace_name": pgutil.TextOrEmpty(row.WorkspaceName),
			"type": row.Type, "health": row.LatestHealth, "last_metric_at": formatTimestamptz(row.LatestMetricAt),
		}
		if deep, found := h.deepCache.Get(row.ID); found {
			entry["cache_hit_ratio"] = deep.Snapshot.CacheHitRatio
			entry["locks_blocked"] = deep.Snapshot.Locks.Blocked
			entry["replication_status"] = deep.Snapshot.Replication.Status
			entry["latency_p95_ms"] = deep.Snapshot.LatencyP95Ms
		}
		items = append(items, entry)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"databases": items})
}

// mustUser returns the authenticated user already validated by
// authorizeDatabase -- safe to call unchecked here since every caller
// only reaches this after authorizeDatabase's own UserFromContext check
// succeeded.
func mustUser(r *http.Request) services.AuthenticatedUser {
	user, _ := services.UserFromContext(r.Context())
	return user
}
