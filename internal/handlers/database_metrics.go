package handlers

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/services"
)

const (
	defaultDatabaseHistoryRange = 24 * time.Hour
	maxDatabaseHistoryRange     = 30 * 24 * time.Hour
)

type databaseCommonMetricsDTO struct {
	Connections           *int64   `json:"connections,omitempty"`
	ActiveConnections     *int64   `json:"active_connections,omitempty"`
	MaxConnections        *int64   `json:"max_connections,omitempty"`
	MemoryUsageBytes      *int64   `json:"memory_usage_bytes,omitempty"`
	DatabaseSizeBytes     *int64   `json:"database_size_bytes,omitempty"`
	OperationsPerSecond   *float64 `json:"operations_per_second,omitempty"`
	TransactionsPerSecond *float64 `json:"transactions_per_second,omitempty"`
	Errors                *int64   `json:"errors,omitempty"`
	UptimeSeconds         *int64   `json:"uptime_seconds,omitempty"`
}

func commonMetricsDTO(c services.CommonMetrics) databaseCommonMetricsDTO {
	return databaseCommonMetricsDTO{
		Connections: c.Connections, ActiveConnections: c.ActiveConnections, MaxConnections: c.MaxConnections,
		MemoryUsageBytes: c.MemoryUsageBytes, DatabaseSizeBytes: c.DatabaseSizeBytes, OperationsPerSecond: c.OperationsPerSecond,
		TransactionsPerSecond: c.TransactionsPerSecond, Errors: c.Errors, UptimeSeconds: c.UptimeSeconds,
	}
}

type databaseMetricsCurrentResponse struct {
	Status            string                    `json:"status"`
	CapturedAt        *string                   `json:"captured_at,omitempty"`
	StaleAfterSeconds int64                     `json:"stale_after_seconds"`
	MonitoringEnabled bool                      `json:"monitoring_enabled"`
	ConnectionStatus  string                    `json:"connection_status"`
	Health            string                    `json:"health,omitempty"`
	MetricsStatus     string                    `json:"metrics_status,omitempty"`
	Common            *databaseCommonMetricsDTO `json:"common,omitempty"`
	Details           map[string]any            `json:"details,omitempty"`
}

// MetricsCurrent handles GET /api/databases/:id/metrics/current: the
// latest cached fast-metrics sample, never triggering a new connection
// on read (spec §46 -- one collector, many viewers).
func (h *DatabaseHandler) MetricsCurrent(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseView)
	if !ok {
		return
	}
	resp := databaseMetricsCurrentResponse{
		StaleAfterSeconds: int64(h.staleAfter.Seconds()), MonitoringEnabled: db.MonitoringEnabled, ConnectionStatus: db.ConnectionStatus,
		Status: "NO_DATA",
	}
	if entry, found := h.cache.Get(db.ID); found {
		formatted := entry.CapturedAt.Format(time.RFC3339)
		resp.CapturedAt = &formatted
		resp.Status = string(entry.Snapshot.HealthStatus)
		resp.Health = string(entry.Snapshot.HealthStatus)
		resp.MetricsStatus = entry.Snapshot.MetricsStatus
		common := commonMetricsDTO(entry.Snapshot.Common)
		resp.Common = &common
		resp.Details = entry.Snapshot.Details
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

type databaseMetricPointDTO struct {
	CapturedAt            string   `json:"captured_at"`
	HealthStatus          string   `json:"health_status,omitempty"`
	MetricsStatus         string   `json:"metrics_status,omitempty"`
	Connections           *int32   `json:"connections,omitempty"`
	ActiveConnections     *int32   `json:"active_connections,omitempty"`
	MaxConnections        *int32   `json:"max_connections,omitempty"`
	MemoryUsageBytes      *int64   `json:"memory_usage_bytes,omitempty"`
	DatabaseSizeBytes     *int64   `json:"database_size_bytes,omitempty"`
	OperationsPerSecond   *float64 `json:"operations_per_second,omitempty"`
	TransactionsPerSecond *float64 `json:"transactions_per_second,omitempty"`
}

// MetricsHistory handles GET /api/databases/:id/metrics/history?from=&to=.
func (h *DatabaseHandler) MetricsHistory(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseView)
	if !ok {
		return
	}
	from, to := parseDatabaseHistoryRange(r, defaultDatabaseHistoryRange, maxDatabaseHistoryRange)
	rows, err := h.store.ListStandaloneDatabaseMetricsSince(r.Context(), generated.ListStandaloneDatabaseMetricsSinceParams{DatabaseID: db.ID, CapturedAt: pgutil.Timestamptz(from)})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load metrics history")
		return
	}
	points := make([]databaseMetricPointDTO, 0, len(rows))
	for _, row := range rows {
		if row.CapturedAt.Time.After(to) {
			continue
		}
		points = append(points, databaseMetricPointDTO{
			CapturedAt: row.CapturedAt.Time.Format(time.RFC3339), HealthStatus: row.HealthStatus, MetricsStatus: row.MetricsStatus,
			Connections: pgutil.Int4Ptr(row.Connections), ActiveConnections: pgutil.Int4Ptr(row.ActiveConnections), MaxConnections: pgutil.Int4Ptr(row.MaxConnections),
			MemoryUsageBytes: pgutil.Int8Ptr(row.MemoryUsageBytes), DatabaseSizeBytes: pgutil.Int8Ptr(row.DatabaseSizeBytes),
			OperationsPerSecond: pgutil.Float8Ptr(row.OperationsPerSecond), TransactionsPerSecond: pgutil.Float8Ptr(row.TransactionsPerSecond),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"from": from.Format(time.RFC3339), "to": to.Format(time.RFC3339), "points": points})
}

// MetricsStream handles GET /api/databases/:id/metrics/stream: a
// WebSocket pushing the latest cached fast-metrics sample once per
// DATABASE_METRICS_STREAM_INTERVAL -- mirrors DockerHandler.Stream's
// single-collector-many-viewers shape exactly (spec §46/#67): it never
// opens a database connection itself, only reads DatabaseMetricsCache.
func (h *DatabaseHandler) MetricsStream(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseView)
	if !ok {
		return
	}
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
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if !h.pushCurrentMetricsSample(conn, db.ID) {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-closed:
			return
		case <-ticker.C:
			if !h.pushCurrentMetricsSample(conn, db.ID) {
				return
			}
		}
	}
}

// pushCurrentMetricsSample writes the database's latest cached fast
// metrics sample (or a "waiting" frame if nothing has been collected for
// it yet) as one JSON frame. Returns false on a write failure
// (connection gone), so the caller's loop can stop.
func (h *DatabaseHandler) pushCurrentMetricsSample(conn *websocket.Conn, databaseID uuid.UUID) bool {
	entry, ok := h.cache.Get(databaseID)
	if !ok {
		return conn.WriteJSON(map[string]any{"type": "waiting", "reason": "no metrics collected yet for this database"}) == nil
	}
	common := commonMetricsDTO(entry.Snapshot.Common)
	return conn.WriteJSON(map[string]any{
		"captured_at": entry.CapturedAt.Format(time.RFC3339), "health": string(entry.Snapshot.HealthStatus),
		"metrics_status": entry.Snapshot.MetricsStatus, "common": common, "details": entry.Snapshot.Details,
	}) == nil
}

// parseDatabaseHistoryRange parses ?from=&to= (RFC3339), defaulting to
// the last defaultRange and clamped to maxRange -- identical bounding
// discipline to MonitoringHandler.GetHistory (Step 6 spec §38).
func parseDatabaseHistoryRange(r *http.Request, defaultRange, maxRange time.Duration) (time.Time, time.Time) {
	now := time.Now()
	from := now.Add(-defaultRange)
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
	if to.Sub(from) > maxRange {
		from = to.Add(-maxRange)
	}
	return from, to
}
