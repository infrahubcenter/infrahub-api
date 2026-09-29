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

// DatabasePerformanceThresholds are the configurable Step 13 thresholds
// -- never hardcoded inline, always read from config.go/env vars.
type DatabasePerformanceThresholds struct {
	CacheHitWarning, CacheHitCritical float64
	LockWarningCount                  int64
	SlowQueryMs                       float64
	GrowthWarningPercent              float64
}

// databaseHighTempIOThresholdBytes is a fixed, documented operational
// threshold (100MB of new temp-file activity in one deep cycle).
const databaseHighTempIOThresholdBytes = 100 * 1024 * 1024

// DatabaseDeepMetricsService collects the expensive, less-frequent
// performance dimensions: query rankings, locks/waits, replication
// detail, cache/checkpoint/WAL activity, and storage growth. Deliberately
// separate from DatabaseMetricsService (the fast/common cycle) -- a slow
// or failing deep cycle never touches connection_status/health_status,
// which remain the fast cycle's exclusive responsibility.
type DatabaseDeepMetricsService struct {
	store             *repository.Store
	credentials       *StandaloneDatabaseCredentialService
	cache             *DatabaseDeepMetricsCache
	connectionTimeout time.Duration
	commandTimeout    time.Duration
	thresholds        DatabasePerformanceThresholds
	queryTextCapture  bool
	queryTextMaxBytes int32
	limiter           *DatabaseConnectionLimiter
}

// NewDatabaseDeepMetricsService creates a DatabaseDeepMetricsService.
func NewDatabaseDeepMetricsService(
	store *repository.Store, credentials *StandaloneDatabaseCredentialService, cache *DatabaseDeepMetricsCache,
	connectionTimeout, commandTimeout time.Duration, thresholds DatabasePerformanceThresholds,
	queryTextCapture bool, queryTextMaxBytes int32,
) *DatabaseDeepMetricsService {
	return &DatabaseDeepMetricsService{
		store: store, credentials: credentials, cache: cache,
		connectionTimeout: connectionTimeout, commandTimeout: commandTimeout, thresholds: thresholds,
		queryTextCapture: queryTextCapture, queryTextMaxBytes: queryTextMaxBytes,
	}
}

// SetConnectionLimiter mirrors DatabaseMetricsService's identical method
// -- both services share one DATABASE_MONITOR_MAX_CONNECTIONS cap.
func (s *DatabaseDeepMetricsService) SetConnectionLimiter(l *DatabaseConnectionLimiter) {
	s.limiter = l
}

// CollectDeep runs one deep-metrics cycle for a single standalone
// database. Never fails the whole cycle just because one sub-collection
// (e.g. pg_stat_statements) is unavailable.
func (s *DatabaseDeepMetricsService) CollectDeep(ctx context.Context, db generated.GetDatabaseForMonitoringRow) error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, s.connectionTimeout)
	defer cancel()

	username, password, err := s.credentials.GetCredential(ctx, db.ID)
	if err != nil {
		recordMonitoringFailure(ctx, s.store, db.ID, "DEEP", "no monitoring credential configured")
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

	result, deepErr := CollectDirectDeepMetrics(ctx, conn)
	if deepErr != nil {
		recordMonitoringFailure(ctx, s.store, db.ID, "DEEP", deepErr.Error())
		return nil
	}

	prev, hasPrev := s.previousDeepCounters(ctx, db.ID)
	if deepDetectRestart(result, prev, hasPrev) {
		hasPrev = false
	}
	commitsPerSec := deepRate(result, prev, hasPrev, "xact_commit")
	rollbacksPerSec := deepRate(result, prev, hasPrev, "xact_rollback")
	tempFilesDelta := deepDelta(result, prev, hasPrev, "temp_files")
	tempBytesDelta := deepDelta(result, prev, hasPrev, "temp_bytes")
	walBytesDelta := deepDelta(result, prev, hasPrev, "wal_lsn_bytes")

	growthRate, growthOK := s.computeGrowthRate(ctx, db.ID)

	var avgTimes []float64
	for _, q := range result.Queries {
		if q.AvgTimeMs != nil {
			avgTimes = append(avgTimes, *q.AvgTimeMs)
		}
	}
	p50, p95, p99 := ComputeLatencyPercentiles(avgTimes)

	metricsStatus := "COMPLETE"
	if result.Partial || result.Warning != "" {
		metricsStatus = "PARTIAL"
	}

	details := map[string]any{}
	if result.Warning != "" {
		details["warning"] = result.Warning
	}
	if len(result.Sessions) > 0 {
		details["sessions"] = sessionsToDetail(result.Sessions)
	}
	rawCopy := make(map[string]any, len(result.RawCounters))
	for k, v := range result.RawCounters {
		rawCopy[k] = v
	}
	details["_raw_counters"] = rawCopy
	detailsJSON, _ := json.Marshal(details)

	var growthParam pgtype.Float8
	if growthOK {
		growthParam = pgtype.Float8{Float64: growthRate, Valid: true}
	}

	deepRow, err := s.store.CreateStandaloneDatabaseDeepMetric(ctx, generated.CreateStandaloneDatabaseDeepMetricParams{
		DatabaseID:    db.ID,
		CacheHitRatio: float8FromPtr(result.CacheHitRatio), Deadlocks: int4FromPtr(result.Deadlocks),
		TempFiles: int8FromPtr(tempFilesDelta), TempBytes: int8FromPtr(tempBytesDelta), WalBytes: int8FromPtr(walBytesDelta),
		CheckpointsTimed: int4FromPtr(result.CheckpointsTimed), CheckpointsReq: int4FromPtr(result.CheckpointsReq),
		CommitsPerSec: float8FromPtr(commitsPerSec), RollbacksPerSec: float8FromPtr(rollbacksPerSec),
		LocksWaiting: int4FromPtr(result.Locks.Waiting), LocksBlocked: int4FromPtr(result.Locks.Blocked),
		ReplicationStatus: pgutil.Text(result.Replication.Status), ReplicationLagSeconds: float8FromPtr(result.Replication.LagSeconds),
		ReplicaCount: int4FromPtr(result.Replication.ReplicaCount),
		LatencyP50Ms: float8FromPtr(p50), LatencyP95Ms: float8FromPtr(p95), LatencyP99Ms: float8FromPtr(p99),
		GrowthBytesPerDay: growthParam, MetricsStatus: metricsStatus, Details: detailsJSON,
	})
	if err != nil {
		return fmt.Errorf("store deep metric snapshot: %w", err)
	}

	s.persistQueryMetrics(ctx, db.ID, deepRow.CapturedAt, result.Queries)

	s.cache.Set(db.ID, DeepMetricsSample{
		CacheHitRatio: result.CacheHitRatio, Locks: result.Locks, Replication: result.Replication,
		LatencyP50Ms: p50, LatencyP95Ms: p95, LatencyP99Ms: p99, GrowthBytesPerDay: growthParamPtr(growthParam),
		MetricsStatus: metricsStatus, Sessions: result.Sessions, TopQueries: result.Queries,
	}, deepRow.CapturedAt.Time)

	s.syncRecommendations(ctx, db, result, p95, growthRate, growthOK, tempBytesDelta)
	recordMonitoringSuccess(ctx, s.store, db.ID, "DEEP", time.Since(start))
	return nil
}

func (s *DatabaseDeepMetricsService) persistQueryMetrics(ctx context.Context, databaseID uuid.UUID, capturedAt pgtype.Timestamptz, queries []QueryMetric) {
	for _, q := range queries {
		normalizedText := pgtype.Text{}
		if s.queryTextCapture && q.NormalizedText != "" {
			normalizedText = pgutil.Text(TruncateQueryText(q.NormalizedText, int(s.queryTextMaxBytes)))
		}
		_, _ = s.store.UpsertStandaloneDatabaseQueryMetric(ctx, generated.UpsertStandaloneDatabaseQueryMetricParams{
			DatabaseID: databaseID, QueryFingerprint: q.Fingerprint, CapturedAt: capturedAt,
			Calls: int8FromPtr(q.Calls), TotalTimeMs: float8FromPtr(q.TotalTimeMs), AvgTimeMs: float8FromPtr(q.AvgTimeMs),
			Rows: int8FromPtr(q.Rows), BlocksRead: int8FromPtr(q.BlocksRead), BlocksHit: int8FromPtr(q.BlocksHit),
			DatabaseName: pgutil.Text(q.DatabaseName), DatabaseUser: pgutil.Text(q.DatabaseUser), NormalizedText: normalizedText,
		})
	}
}

func (s *DatabaseDeepMetricsService) computeGrowthRate(ctx context.Context, databaseID uuid.UUID) (float64, bool) {
	rows, err := s.store.GetStandaloneDatabaseSizeHistorySince(ctx, generated.GetStandaloneDatabaseSizeHistorySinceParams{
		DatabaseID: databaseID, CapturedAt: pgutil.Timestamptz(time.Now().Add(-7 * 24 * time.Hour)),
	})
	if err != nil || len(rows) < 2 {
		return 0, false
	}
	samples := make([]SizeSample, 0, len(rows))
	for _, r := range rows {
		if !r.DatabaseSizeBytes.Valid {
			continue
		}
		samples = append(samples, SizeSample{CapturedAtUnix: r.CapturedAt.Time.Unix(), SizeBytes: r.DatabaseSizeBytes.Int64})
	}
	return ComputeGrowthRate(samples)
}

func (s *DatabaseDeepMetricsService) previousDeepCounters(ctx context.Context, databaseID uuid.UUID) (map[string]float64, bool) {
	prev, err := s.store.GetLatestStandaloneDatabaseDeepMetric(ctx, databaseID)
	if err != nil {
		return nil, false
	}
	var details map[string]any
	if err := json.Unmarshal(prev.Details, &details); err != nil {
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

func deepDetectRestart(result DeepMetricsResult, prev map[string]float64, hasPrev bool) bool {
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

func deepRate(result DeepMetricsResult, prev map[string]float64, hasPrev bool, key string) *float64 {
	if !hasPrev {
		return nil
	}
	cur, curOK := result.RawCounters[key]
	old, oldOK := prev[key]
	if !curOK || !oldOK || cur < old {
		return nil
	}
	prevAtUnix, ok := prev["_captured_at_unix"]
	if !ok {
		return nil
	}
	elapsed := time.Since(time.Unix(int64(prevAtUnix), 0)).Seconds()
	if elapsed <= 0 {
		return nil
	}
	rate := (cur - old) / elapsed
	return &rate
}

func deepDelta(result DeepMetricsResult, prev map[string]float64, hasPrev bool, key string) *int64 {
	if !hasPrev {
		return nil
	}
	cur, curOK := result.RawCounters[key]
	old, oldOK := prev[key]
	if !curOK || !oldOK || cur < old {
		return nil
	}
	delta := int64(cur - old)
	return &delta
}

func sessionsToDetail(sessions []SessionInfo) []map[string]any {
	out := make([]map[string]any, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, map[string]any{
			"pid": s.PID, "database": s.Database, "user": s.User, "duration_seconds": s.DurationSeconds,
			"state": s.State, "wait_event_type": s.WaitEventType, "wait_event": s.WaitEvent,
			"application_name": s.ApplicationName, "blocking_pids": s.BlockingPIDs,
		})
	}
	return out
}

func growthParamPtr(v pgtype.Float8) *float64 {
	if !v.Valid {
		return nil
	}
	f := v.Float64
	return &f
}

// syncRecommendations creates/resolves the deep-cycle recommendation
// types from real, just-collected evidence -- deduplicated via the same
// source_type/source_id unique index every other recommendation in this
// project uses, never fabricating a warning the metrics don't support.
func (s *DatabaseDeepMetricsService) syncRecommendations(
	ctx context.Context, db generated.GetDatabaseForMonitoringRow, result DeepMetricsResult,
	p95 *float64, growthBytesPerDay float64, growthOK bool, tempBytesDelta *int64,
) {
	resourceID := db.ResourceID

	if result.Locks.Blocked != nil && *result.Locks.Blocked >= s.thresholds.LockWarningCount {
		severity := "MEDIUM"
		if *result.Locks.Blocked >= s.thresholds.LockWarningCount*2 {
			severity = "HIGH"
		}
		upsertDatabaseRecommendation(ctx, s.store, resourceID, db.ID, "database_lock_contention", "DATABASE_LOCK_CONTENTION", severity,
			fmt.Sprintf("%s has %d blocked session(s)", db.Type, *result.Locks.Blocked))
	} else {
		resolveDatabaseRecommendation(ctx, s.store, "database_lock_contention", db.ID)
	}

	if result.CacheHitRatio != nil {
		switch {
		case *result.CacheHitRatio < s.thresholds.CacheHitCritical:
			upsertDatabaseRecommendation(ctx, s.store, resourceID, db.ID, "database_low_cache_hit", "DATABASE_LOW_CACHE_HIT", "HIGH",
				fmt.Sprintf("%s cache hit ratio is %.1f%%, below the configured threshold", db.Type, *result.CacheHitRatio))
		case *result.CacheHitRatio < s.thresholds.CacheHitWarning:
			upsertDatabaseRecommendation(ctx, s.store, resourceID, db.ID, "database_low_cache_hit", "DATABASE_LOW_CACHE_HIT", "MEDIUM",
				fmt.Sprintf("%s cache hit ratio is %.1f%%, below the configured threshold", db.Type, *result.CacheHitRatio))
		default:
			resolveDatabaseRecommendation(ctx, s.store, "database_low_cache_hit", db.ID)
		}
	}

	if tempBytesDelta != nil && *tempBytesDelta > databaseHighTempIOThresholdBytes {
		upsertDatabaseRecommendation(ctx, s.store, resourceID, db.ID, "database_high_temp_io", "DATABASE_HIGH_TEMP_IO", "MEDIUM",
			fmt.Sprintf("%s temporary file activity increased (%s since last check)", db.Type, formatByteCount(*tempBytesDelta)))
	} else {
		resolveDatabaseRecommendation(ctx, s.store, "database_high_temp_io", db.ID)
	}

	if result.Replication.LagSeconds != nil && *result.Replication.LagSeconds > 10 {
		upsertDatabaseRecommendation(ctx, s.store, resourceID, db.ID, "database_replication_lag", "DATABASE_REPLICATION_LAG", "MEDIUM",
			fmt.Sprintf("%s replication lag is %.1fs", db.Type, *result.Replication.LagSeconds))
	} else if result.Replication.Status != "NOT_CONFIGURED" {
		resolveDatabaseRecommendation(ctx, s.store, "database_replication_lag", db.ID)
	}

	if growthOK {
		if size, sizeOK := s.currentDatabaseSizeBytes(ctx, db.ID); sizeOK && size > 0 {
			projectedPercent := (growthBytesPerDay * 7 / float64(size)) * 100
			if projectedPercent > s.thresholds.GrowthWarningPercent {
				upsertDatabaseRecommendation(ctx, s.store, resourceID, db.ID, "database_growth_high", "DATABASE_GROWTH_HIGH", "MEDIUM",
					fmt.Sprintf("%s storage is projected to grow %.1f%% over the next 7 days at the current rate", db.Type, projectedPercent))
			} else {
				resolveDatabaseRecommendation(ctx, s.store, "database_growth_high", db.ID)
			}
		}
	}

	var worst QueryMetric
	haveWorst := false
	for _, q := range result.Queries {
		if q.AvgTimeMs == nil {
			continue
		}
		if !haveWorst || *q.AvgTimeMs > *worst.AvgTimeMs {
			worst, haveWorst = q, true
		}
	}
	if haveWorst && *worst.AvgTimeMs >= s.thresholds.SlowQueryMs {
		calls := int64(0)
		if worst.Calls != nil {
			calls = *worst.Calls
		}
		upsertDatabaseRecommendation(ctx, s.store, resourceID, db.ID, "database_slow_query", "DATABASE_SLOW_QUERY", "MEDIUM",
			fmt.Sprintf("%s: query %s averages %.0fms over %d call(s)", db.Type, shortFingerprint(worst.Fingerprint), *worst.AvgTimeMs, calls))
	} else {
		resolveDatabaseRecommendation(ctx, s.store, "database_slow_query", db.ID)
	}

	if p95 != nil && *p95 >= s.thresholds.SlowQueryMs {
		upsertDatabaseRecommendation(ctx, s.store, resourceID, db.ID, "database_high_query_latency", "DATABASE_HIGH_QUERY_LATENCY", "MEDIUM",
			fmt.Sprintf("%s query p95 latency is %.0fms", db.Type, *p95))
	} else {
		resolveDatabaseRecommendation(ctx, s.store, "database_high_query_latency", db.ID)
	}

	if evictRate, ok := result.RawCounters["evicted_keys"]; ok && evictRate > 0 {
		upsertDatabaseRecommendation(ctx, s.store, resourceID, db.ID, "database_redis_evictions", "DATABASE_REDIS_EVICTIONS", "MEDIUM",
			fmt.Sprintf("%s is evicting keys (%.1f/sec)", db.Type, evictRate))
	} else {
		resolveDatabaseRecommendation(ctx, s.store, "database_redis_evictions", db.ID)
	}
}

func formatByteCount(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func shortFingerprint(f string) string {
	if len(f) <= 12 {
		return f
	}
	return f[:12]
}

func (s *DatabaseDeepMetricsService) currentDatabaseSizeBytes(ctx context.Context, databaseID uuid.UUID) (int64, bool) {
	snapshot, err := s.store.GetLatestStandaloneDatabaseMetric(ctx, databaseID)
	if err != nil || !snapshot.DatabaseSizeBytes.Valid {
		return 0, false
	}
	return snapshot.DatabaseSizeBytes.Int64, true
}
