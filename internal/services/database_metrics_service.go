package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// DatabaseMetricsService collects one fast-cycle snapshot for one
// standalone database instance: connect directly (TCP/TLS, spec §2),
// run the adapter's single combined metrics query/command, compute rates
// from the previous snapshot's raw counters, classify health, persist,
// cache, and sync recommendations.
type DatabaseMetricsService struct {
	store             *repository.Store
	credentials       *StandaloneDatabaseCredentialService
	cache             *DatabaseMetricsCache
	connectionTimeout time.Duration // DATABASE_CONNECTION_TIMEOUT
	commandTimeout    time.Duration // DATABASE_QUERY_TIMEOUT
	thresholds        DatabaseHealthThresholds
	limiter           *DatabaseConnectionLimiter
}

// NewDatabaseMetricsService creates a DatabaseMetricsService.
func NewDatabaseMetricsService(
	store *repository.Store, credentials *StandaloneDatabaseCredentialService, cache *DatabaseMetricsCache,
	connectionTimeout, commandTimeout time.Duration, thresholds DatabaseHealthThresholds,
) *DatabaseMetricsService {
	return &DatabaseMetricsService{
		store: store, credentials: credentials, cache: cache,
		connectionTimeout: connectionTimeout, commandTimeout: commandTimeout, thresholds: thresholds,
	}
}

// SetConnectionLimiter wires in the shared DATABASE_MONITOR_MAX_CONNECTIONS
// cap (spec §47).
func (s *DatabaseMetricsService) SetConnectionLimiter(l *DatabaseConnectionLimiter) { s.limiter = l }

// CollectOne runs one fast metrics-collection cycle for a single
// standalone database. Never fails the whole collection just because one
// optional sub-metric is unavailable -- MetricsResult.Partial and
// metrics_status carry that distinction through to storage. The whole
// cycle is bounded by DATABASE_CONNECTION_TIMEOUT.
func (s *DatabaseMetricsService) CollectOne(ctx context.Context, db generated.GetDatabaseForMonitoringRow) error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, s.connectionTimeout)
	defer cancel()

	username, password, err := s.credentials.GetCredential(ctx, db.ID)
	if err != nil {
		s.recordUnavailable(ctx, db.ID, ConnUNAVAILABLE)
		return nil
	}

	if s.limiter != nil {
		if err := s.limiter.Acquire(ctx); err != nil {
			return nil
		}
		defer s.limiter.Release()
	}

	conn := DirectDatabaseConnection{
		Type: DatabaseType(db.Type), Host: db.Host, Port: int(db.Port), Username: username, Password: password,
		Database: pgutil.TextOrEmpty(db.DatabaseName), TLSEnabled: db.TlsEnabled, TLSSkipVerify: db.TlsSkipVerify,
		ConnectTimeout: s.connectionTimeout, QueryTimeout: s.commandTimeout,
	}

	result, metricsErr := CollectDirectDatabaseMetrics(ctx, conn)
	connStatus := ConnectionStatusFromError(metricsErr)
	_, _ = s.store.UpdateDatabaseConnectionStatus(ctx, generated.UpdateDatabaseConnectionStatusParams{ID: db.ID, ConnectionStatus: string(connStatus)})
	if metricsErr != nil {
		s.recordUnavailable(ctx, db.ID, connStatus)
		return nil
	}

	prev, hasPrev := s.previousCounters(ctx, db.ID)
	if detectFastRestart(result, prev, hasPrev) {
		hasPrev = false // never compute a rate across a restart
	}
	s.applyRates(&result, prev, hasPrev)

	maxMemory := detailInt64(result.Details, "max_memory_bytes")
	health := ComputeDatabaseHealth(result.Common, maxMemory, connStatus, s.thresholds)
	metricsStatus := "COMPLETE"
	if result.Partial {
		metricsStatus = "PARTIAL"
	}

	detailsJSON, _ := json.Marshal(result.Details)
	capturedAt := time.Now()
	err = s.store.InsertStandaloneDatabaseMetric(ctx, generated.InsertStandaloneDatabaseMetricParams{
		DatabaseID: db.ID, CapturedAt: pgutil.Timestamptz(capturedAt),
		Connections: int4FromPtr(result.Common.Connections), ActiveConnections: int4FromPtr(result.Common.ActiveConnections),
		MaxConnections: int4FromPtr(result.Common.MaxConnections), MemoryUsageBytes: int8FromPtr(result.Common.MemoryUsageBytes),
		DatabaseSizeBytes: int8FromPtr(result.Common.DatabaseSizeBytes), OperationsPerSecond: float8FromPtr(result.Common.OperationsPerSecond),
		TransactionsPerSecond: float8FromPtr(result.Common.TransactionsPerSecond), Errors: int4FromPtr(result.Common.Errors),
		UptimeSeconds: int8FromPtr(result.Common.UptimeSeconds), HealthStatus: string(health), MetricsStatus: metricsStatus,
		MetricDetails: detailsJSON,
	})
	if err != nil {
		return fmt.Errorf("store metric snapshot: %w", err)
	}

	s.cache.Set(db.ID, DatabaseMetricsSample{
		Common: result.Common, Details: result.Details, HealthStatus: health, MetricsStatus: metricsStatus,
	}, capturedAt)

	s.syncRecommendations(ctx, db, result, health)
	recordMonitoringSuccess(ctx, s.store, db.ID, "FAST", time.Since(start))
	return nil
}

func (s *DatabaseMetricsService) recordUnavailable(ctx context.Context, databaseID uuid.UUID, connStatus ConnectionTestStatus) {
	defer recordMonitoringFailure(ctx, s.store, databaseID, "FAST", string(connStatus))
	_, _ = s.store.UpdateDatabaseConnectionStatus(ctx, generated.UpdateDatabaseConnectionStatusParams{ID: databaseID, ConnectionStatus: string(connStatus)})
	health := ComputeDatabaseHealth(CommonMetrics{}, 0, connStatus, s.thresholds)
	capturedAt := time.Now()
	err := s.store.InsertStandaloneDatabaseMetric(ctx, generated.InsertStandaloneDatabaseMetricParams{
		DatabaseID: databaseID, CapturedAt: pgutil.Timestamptz(capturedAt), HealthStatus: string(health), MetricsStatus: "FAILED", MetricDetails: []byte("{}"),
	})
	if err == nil {
		s.cache.Set(databaseID, DatabaseMetricsSample{HealthStatus: health, MetricsStatus: "FAILED"}, capturedAt)
	}
}

// previousCounters loads the most recent snapshot's raw counters (stored
// inside metric_details under a reserved "_raw_counters" key) so a rate
// can be computed without a second collection round trip.
func (s *DatabaseMetricsService) previousCounters(ctx context.Context, databaseID uuid.UUID) (map[string]float64, bool) {
	prev, err := s.store.GetLatestStandaloneDatabaseMetric(ctx, databaseID)
	if err != nil {
		return nil, false
	}
	var details map[string]any
	if err := json.Unmarshal(prev.MetricDetails, &details); err != nil {
		return nil, false
	}
	raw, ok := details["_raw_counters"].(map[string]any)
	if !ok {
		return nil, false
	}
	counters := make(map[string]float64, len(raw)+1)
	for k, v := range raw {
		if f, ok := v.(float64); ok {
			counters[k] = f
		}
	}
	counters["_captured_at_unix"] = float64(prev.CapturedAt.Time.Unix())
	return counters, true
}

func detectFastRestart(result MetricsResult, prev map[string]float64, hasPrev bool) bool {
	if !hasPrev {
		return false
	}
	for k, v := range result.RawCounters {
		if prevV, ok := prev[k]; ok && v < prevV {
			return true
		}
	}
	return false
}

// applyRates computes ops/sec-style rates from cumulative counters:
// (current - previous) / elapsed_seconds, never treating the counter
// itself as a rate, never a negative rate.
func (s *DatabaseMetricsService) applyRates(result *MetricsResult, prev map[string]float64, hasPrev bool) {
	if result.Details == nil {
		result.Details = map[string]any{}
	}
	rawCopy := make(map[string]any, len(result.RawCounters))
	for k, v := range result.RawCounters {
		rawCopy[k] = v
	}
	if !hasPrev {
		result.Details["_raw_counters"] = rawCopy
		return
	}
	prevAtUnix, ok := prev["_captured_at_unix"]
	elapsed := time.Since(time.Unix(int64(prevAtUnix), 0)).Seconds()
	if !ok || elapsed <= 0 {
		result.Details["_raw_counters"] = rawCopy
		return
	}

	rate := func(key string) (float64, bool) {
		cur, curOK := result.RawCounters[key]
		old, oldOK := prev[key]
		if !curOK || !oldOK || cur < old {
			return 0, false
		}
		return (cur - old) / elapsed, true
	}

	switch {
	case hasCounter(result.RawCounters, "xact_commit"):
		commitRate, _ := rate("xact_commit")
		rollbackRate, _ := rate("xact_rollback")
		total := commitRate + rollbackRate
		result.Common.TransactionsPerSecond = &total
	case hasCounter(result.RawCounters, "queries"):
		if r, ok := rate("queries"); ok {
			result.Common.OperationsPerSecond = &r
		}
	case hasCounter(result.RawCounters, "op_insert"):
		sum := 0.0
		any := false
		for _, k := range []string{"op_insert", "op_query", "op_update", "op_delete", "op_getmore", "op_command"} {
			if r, ok := rate(k); ok {
				sum += r
				any = true
			}
		}
		if any {
			result.Common.OperationsPerSecond = &sum
		}
	case hasCounter(result.RawCounters, "total_commands_processed"):
		if r, ok := rate("total_commands_processed"); ok {
			result.Common.OperationsPerSecond = &r
		}
	}

	result.Details["_raw_counters"] = rawCopy
}

// syncRecommendations creates/resolves the fast-cycle recommendation
// types from real, just-collected evidence, reusing the exact same
// upsert/resolve-by-source infrastructure (Step 7) every other feature in
// this project uses, keyed by the database's own resource_id + this
// database's own row ID for natural dedup.
func (s *DatabaseMetricsService) syncRecommendations(ctx context.Context, db generated.GetDatabaseForMonitoringRow, result MetricsResult, health HealthStatus) {
	if health == HealthOffline {
		upsertDatabaseRecommendation(ctx, s.store, db.ResourceID, db.ID, "database_unavailable", "DATABASE_UNAVAILABLE", "HIGH",
			fmt.Sprintf("%s is unavailable", db.Type))
	} else {
		resolveDatabaseRecommendation(ctx, s.store, "database_unavailable", db.ID)
	}

	s.syncThresholdRecommendation(ctx, db, "database_connection_pressure", "DATABASE_CONNECTION_PRESSURE",
		connectionPressureSeverity(result.Common, s.thresholds), fmt.Sprintf("%s connection utilization is elevated", db.Type))
	s.syncThresholdRecommendation(ctx, db, "database_memory_pressure", "DATABASE_MEMORY_PRESSURE",
		memoryPressureSeverity(result.Common, result.Details, s.thresholds), fmt.Sprintf("%s memory utilization is elevated", db.Type))

	if blocked, ok := result.Details["blocked_clients"].(int64); ok && blocked > 0 {
		upsertDatabaseRecommendation(ctx, s.store, db.ResourceID, db.ID, "database_redis_blocked_clients", "DATABASE_REDIS_BLOCKED_CLIENTS", "MEDIUM",
			fmt.Sprintf("%s has %d client(s) waiting on blocking operations", db.Type, blocked))
	} else {
		resolveDatabaseRecommendation(ctx, s.store, "database_redis_blocked_clients", db.ID)
	}
}

func (s *DatabaseMetricsService) syncThresholdRecommendation(ctx context.Context, db generated.GetDatabaseForMonitoringRow, sourceType, recType, severity, title string) {
	if severity == "" {
		resolveDatabaseRecommendation(ctx, s.store, sourceType, db.ID)
		return
	}
	upsertDatabaseRecommendation(ctx, s.store, db.ResourceID, db.ID, sourceType, recType, severity, title)
}

// connectionPressureSeverity returns "" (no recommendation) unless
// connection utilization has actually crossed a configured threshold.
func connectionPressureSeverity(common CommonMetrics, t DatabaseHealthThresholds) string {
	if common.Connections == nil || common.MaxConnections == nil || *common.MaxConnections <= 0 {
		return ""
	}
	pct := float64(*common.Connections) / float64(*common.MaxConnections) * 100
	switch {
	case pct >= t.ConnectionCritical:
		return "HIGH"
	case pct >= t.ConnectionWarning:
		return "MEDIUM"
	default:
		return ""
	}
}

// memoryPressureSeverity mirrors connectionPressureSeverity, using
// max_memory_bytes from Details (not every engine reports one; Redis
// only reports it when maxmemory is actually configured, never a fake
// percentage against an unlimited budget).
func memoryPressureSeverity(common CommonMetrics, details map[string]any, t DatabaseHealthThresholds) string {
	maxMemory := detailInt64(details, "max_memory_bytes")
	if common.MemoryUsageBytes == nil || maxMemory <= 0 {
		return ""
	}
	pct := float64(*common.MemoryUsageBytes) / float64(maxMemory) * 100
	switch {
	case pct >= t.MemoryCritical:
		return "HIGH"
	case pct >= t.MemoryWarning:
		return "MEDIUM"
	default:
		return ""
	}
}

func hasCounter(counters map[string]float64, key string) bool {
	_, ok := counters[key]
	return ok
}

func int4FromPtr(v *int64) pgtype.Int4 {
	if v == nil {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: int32(*v), Valid: true}
}

func int8FromPtr(v *int64) pgtype.Int8 {
	if v == nil {
		return pgtype.Int8{}
	}
	return pgtype.Int8{Int64: *v, Valid: true}
}

func float8FromPtr(v *float64) pgtype.Float8 {
	if v == nil {
		return pgtype.Float8{}
	}
	return pgtype.Float8{Float64: *v, Valid: true}
}

func detailInt64(details map[string]any, key string) int64 {
	if details == nil {
		return 0
	}
	switch v := details[key].(type) {
	case int64:
		return v
	case float64:
		return int64(v)
	default:
		return 0
	}
}
