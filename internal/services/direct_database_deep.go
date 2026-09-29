package services

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
)

// CollectDirectDeepMetrics gathers the expensive, less-frequent
// performance dimensions (query rankings, locks, replication, cache) via
// a direct TCP/TLS connection -- one connect, a small fixed number of
// backend-defined, read-only queries per engine, never a client-supplied
// one. Mirrors CollectDirectDatabaseMetrics' per-engine dispatch exactly.
func CollectDirectDeepMetrics(ctx context.Context, conn DirectDatabaseConnection) (DeepMetricsResult, error) {
	switch conn.Type {
	case DBTypePostgreSQL:
		return collectPostgresDeepDirectly(ctx, conn)
	case DBTypeMySQL, DBTypeMariaDB:
		return collectMySQLDeepDirectly(ctx, conn)
	case DBTypeMongoDB:
		return collectMongoDeepDirectly(ctx, conn)
	case DBTypeRedis, DBTypeValkey:
		return collectRedisDeepDirectly(ctx, conn)
	default:
		return DeepMetricsResult{}, fmt.Errorf("%w: %s", ErrDatabaseUnsupported, conn.Type)
	}
}

// --- PostgreSQL ---

const pgDeepScalarDirectQuery = `SELECT ` +
	`(SELECT sum(temp_files) FROM pg_stat_database), ` +
	`(SELECT sum(temp_bytes) FROM pg_stat_database), ` +
	`(SELECT sum(deadlocks) FROM pg_stat_database), ` +
	`(SELECT sum(blks_hit) FROM pg_stat_database), ` +
	`(SELECT sum(blks_read) FROM pg_stat_database), ` +
	`(SELECT sum(xact_commit) FROM pg_stat_database), ` +
	`(SELECT sum(xact_rollback) FROM pg_stat_database), ` +
	`(SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0')::bigint), ` +
	`(SELECT pg_is_in_recovery()::int), ` +
	`(SELECT count(*) FROM pg_stat_replication), ` +
	`(SELECT CASE WHEN pg_is_in_recovery() THEN extract(epoch FROM now() - pg_last_xact_replay_timestamp()) ` +
	`ELSE (SELECT max(extract(epoch FROM replay_lag)) FROM pg_stat_replication) END), ` +
	`(SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'), ` +
	`(SELECT count(*) FROM pg_stat_activity WHERE cardinality(pg_blocking_pids(pid)) > 0)`

// pg_stat_bgwriter's checkpoints_timed/checkpoints_req columns were
// removed in Postgres 17 (moved to the new pg_stat_checkpointer view as
// num_timed/num_requested) -- a managed Postgres 17+ server (this is
// common on DigitalOcean/RDS/Cloud SQL) would otherwise fail this whole
// query with "column \"checkpoints_timed\" does not exist", which used
// to kill the entire deep-metrics cycle (cache hit ratio, locks,
// replication, everything) over two checkpoint counters. Split out and
// tried against both locations so either Postgres generation works.
const pgCheckpointCountersPre17Query = `SELECT checkpoints_timed, checkpoints_req FROM pg_stat_bgwriter`
const pgCheckpointCounters17PlusQuery = `SELECT num_timed, num_requested FROM pg_stat_checkpointer`

const pgSessionsDirectQuery = `SELECT pid, coalesce(datname,''), coalesce(usename,''), ` +
	`coalesce(extract(epoch FROM now() - query_start)::bigint::text,''), coalesce(state,''), ` +
	`coalesce(wait_event_type,''), coalesce(wait_event,''), coalesce(application_name,''), ` +
	`coalesce(array_to_string(pg_blocking_pids(pid), ','),'') ` +
	`FROM pg_stat_activity ` +
	`WHERE pid != pg_backend_pid() AND state IS NOT NULL AND state != 'idle' ` +
	`ORDER BY query_start ASC NULLS LAST LIMIT 50`

const pgStatStatementsDirectQuery = `SELECT queryid::text, calls, total_exec_time, mean_exec_time, rows, ` +
	`shared_blks_hit, shared_blks_read, coalesce(d.datname,''), coalesce(r.rolname,''), query ` +
	`FROM pg_stat_statements s ` +
	`LEFT JOIN pg_database d ON d.oid = s.dbid ` +
	`LEFT JOIN pg_roles r ON r.oid = s.userid ` +
	`ORDER BY total_exec_time DESC LIMIT 50`

func collectPostgresDeepDirectly(ctx context.Context, conn DirectDatabaseConnection) (DeepMetricsResult, error) {
	pgxConn, err := pgx.Connect(ctx, postgresConnString(conn))
	if err != nil {
		return DeepMetricsResult{}, classifyPgError(err)
	}
	defer pgxConn.Close(ctx)

	result := DeepMetricsResult{RawCounters: map[string]float64{}, Details: map[string]any{}}

	var tempFiles, tempBytes, deadlocks, blksHit, blksRead, xactCommit, xactRollback *int64
	var walBytes *int64
	var inRecovery int
	var replicaCount *int64
	var lagSeconds *float64
	var locksWaiting, locksBlocked int64
	err = pgxConn.QueryRow(ctx, pgDeepScalarDirectQuery).Scan(
		&tempFiles, &tempBytes, &deadlocks, &blksHit, &blksRead, &xactCommit, &xactRollback,
		&walBytes, &inRecovery, &replicaCount, &lagSeconds,
		&locksWaiting, &locksBlocked,
	)
	if err != nil {
		// A query executing over an already-established connection
		// failed -- a real SQL/schema error (safe to show: it's the
		// server's own error text, never a connection string), not a
		// connectivity problem, so it must not be labeled as one.
		return DeepMetricsResult{}, fmt.Errorf("%w: %v", ErrDatabaseQueryFailed, err)
	}
	checkpointsTimed, checkpointsReq := queryPostgresCheckpointCounters(ctx, pgxConn)
	if tempFiles != nil {
		result.RawCounters["temp_files"] = float64(*tempFiles)
	}
	if tempBytes != nil {
		result.RawCounters["temp_bytes"] = float64(*tempBytes)
	}
	result.Deadlocks = deadlocks
	if blksHit != nil && blksRead != nil && (*blksHit+*blksRead) > 0 {
		ratio := roundTo(float64(*blksHit)/float64(*blksHit+*blksRead)*100, 2)
		result.CacheHitRatio = &ratio
	}
	if xactCommit != nil {
		result.RawCounters["xact_commit"] = float64(*xactCommit)
	}
	if xactRollback != nil {
		result.RawCounters["xact_rollback"] = float64(*xactRollback)
	}
	result.CheckpointsTimed = checkpointsTimed
	result.CheckpointsReq = checkpointsReq
	if walBytes != nil {
		result.RawCounters["wal_lsn_bytes"] = float64(*walBytes)
	}
	result.Locks = LockMetrics{Waiting: &locksWaiting, Blocked: &locksBlocked}

	switch {
	case lagSeconds != nil:
		result.Replication = ReplicationDetail{Status: "HEALTHY", LagSeconds: lagSeconds, ReplicaCount: replicaCount}
	case replicaCount != nil && *replicaCount > 0:
		result.Replication = ReplicationDetail{Status: "HEALTHY", ReplicaCount: replicaCount}
	default:
		result.Replication = ReplicationDetail{Status: "NOT_CONFIGURED"}
	}

	if rows, err := pgxConn.Query(ctx, pgSessionsDirectQuery); err == nil {
		var sessions []SessionInfo
		for rows.Next() {
			var pid int64
			var db, user, durStr, state, waitType, wait, app, blocking string
			if err := rows.Scan(&pid, &db, &user, &durStr, &state, &waitType, &wait, &app, &blocking); err == nil {
				dur, _ := strconv.ParseInt(durStr, 10, 64)
				var blockingPIDs []string
				if blocking != "" {
					blockingPIDs = strings.Split(blocking, ",")
				}
				sessions = append(sessions, SessionInfo{
					PID: pid, Database: db, User: user, DurationSeconds: dur, State: state,
					WaitEventType: waitType, WaitEvent: wait, ApplicationName: app, BlockingPIDs: blockingPIDs,
				})
			}
		}
		rows.Close()
		result.Sessions = sessions
	} else {
		result.Partial = true
	}

	if rows, err := pgxConn.Query(ctx, pgStatStatementsDirectQuery); err == nil {
		var queries []QueryMetric
		for rows.Next() {
			var queryID, dbName, dbUser, text string
			var calls, rowCount, blocksHit, blocksRead int64
			var totalMs, avgMs float64
			if err := rows.Scan(&queryID, &calls, &totalMs, &avgMs, &rowCount, &blocksHit, &blocksRead, &dbName, &dbUser, &text); err == nil {
				queries = append(queries, QueryMetric{
					Fingerprint: Fingerprint(queryID), Calls: &calls, TotalTimeMs: &totalMs, AvgTimeMs: &avgMs,
					Rows: &rowCount, BlocksHit: &blocksHit, BlocksRead: &blocksRead, DatabaseName: dbName, DatabaseUser: dbUser, NormalizedText: text,
				})
			}
		}
		rows.Close()
		result.Queries = queries
	} else {
		result.Warning = "Query statistics extension unavailable."
	}

	return result, nil
}

// queryPostgresCheckpointCounters tries pre-17's pg_stat_bgwriter first,
// then 17+'s pg_stat_checkpointer -- best-effort, like the sessions/
// pg_stat_statements queries above: nil/nil (never an error) if neither
// location exists on this server, so checkpoint counters simply go
// missing from the result rather than failing deep collection entirely.
func queryPostgresCheckpointCounters(ctx context.Context, conn *pgx.Conn) (timed, req *int64) {
	if err := conn.QueryRow(ctx, pgCheckpointCountersPre17Query).Scan(&timed, &req); err == nil {
		return timed, req
	}
	if err := conn.QueryRow(ctx, pgCheckpointCounters17PlusQuery).Scan(&timed, &req); err == nil {
		return timed, req
	}
	return nil, nil
}

// --- MySQL/MariaDB ---

const mysqlDeepScalarDirectQuery = "SELECT " +
	"(SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='INNODB_BUFFER_POOL_READ_REQUESTS'), " +
	"(SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='INNODB_BUFFER_POOL_READS'), " +
	"(SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='INNODB_ROW_LOCK_WAITS'), " +
	"(SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='INNODB_ROW_LOCK_TIME'), " +
	"(SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='CREATED_TMP_TABLES'), " +
	"(SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='CREATED_TMP_DISK_TABLES')"

const mysqlDigestDirectQuery = "SELECT DIGEST, COUNT_STAR, SUM_TIMER_WAIT/1000000, " +
	"(SUM_TIMER_WAIT/GREATEST(COUNT_STAR,1))/1000000, SUM_ROWS_SENT, coalesce(SCHEMA_NAME,''), DIGEST_TEXT " +
	"FROM performance_schema.events_statements_summary_by_digest " +
	"WHERE DIGEST IS NOT NULL ORDER BY SUM_TIMER_WAIT DESC LIMIT 50"

func collectMySQLDeepDirectly(ctx context.Context, conn DirectDatabaseConnection) (DeepMetricsResult, error) {
	db, err := mysqlOpen(conn)
	if err != nil {
		return DeepMetricsResult{}, err
	}
	defer db.Close()

	result := DeepMetricsResult{RawCounters: map[string]float64{}, Details: map[string]any{}, Replication: ReplicationDetail{Status: "UNKNOWN"}}

	var readReq, reads, rowLockWaits, rowLockTime, tmpTables, tmpDiskTables *string
	row := db.QueryRowContext(ctx, mysqlDeepScalarDirectQuery)
	if err := row.Scan(&readReq, &reads, &rowLockWaits, &rowLockTime, &tmpTables, &tmpDiskTables); err != nil {
		return DeepMetricsResult{}, classifyMySQLError(err)
	}
	if rr, ok := parseFloatPtr(readReq); ok {
		if r, ok := parseFloatPtr(reads); ok && rr > 0 {
			ratio := roundTo((1-r/rr)*100, 2)
			result.CacheHitRatio = &ratio
		}
	}
	if v, ok := parseFloatPtr(rowLockWaits); ok {
		result.RawCounters["innodb_row_lock_waits"] = v
	}
	if v, ok := parseFloatPtr(rowLockTime); ok {
		result.RawCounters["innodb_row_lock_time_ms"] = v
	}
	if v, ok := parseFloatPtr(tmpTables); ok {
		result.RawCounters["created_tmp_tables"] = v
	}
	if v, ok := parseFloatPtr(tmpDiskTables); ok {
		result.RawCounters["created_tmp_disk_tables"] = v
	}

	rows, err := db.QueryContext(ctx, mysqlDigestDirectQuery)
	if err != nil {
		result.Warning = "Query statistics extension unavailable."
		return result, nil
	}
	defer rows.Close()
	var queries []QueryMetric
	for rows.Next() {
		var digest, dbName, text string
		var calls, rowCount int64
		var totalMs, avgMs float64
		if err := rows.Scan(&digest, &calls, &totalMs, &avgMs, &rowCount, &dbName, &text); err == nil && digest != "" {
			queries = append(queries, QueryMetric{
				Fingerprint: Fingerprint(digest), Calls: &calls, TotalTimeMs: &totalMs, AvgTimeMs: &avgMs,
				Rows: &rowCount, DatabaseName: dbName, NormalizedText: text,
			})
		}
	}
	result.Queries = queries
	return result, nil
}

func parseFloatPtr(v *string) (float64, bool) {
	if v == nil {
		return 0, false
	}
	f, err := strconv.ParseFloat(*v, 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

// --- MongoDB ---

func collectMongoDeepDirectly(ctx context.Context, conn DirectDatabaseConnection) (DeepMetricsResult, error) {
	client, err := mongoConnect(ctx, conn)
	if err != nil {
		return DeepMetricsResult{}, err
	}
	defer client.Disconnect(ctx)

	result := DeepMetricsResult{Details: map[string]any{}, Replication: ReplicationDetail{Status: "NOT_CONFIGURED"}}
	admin := client.Database("admin")

	var status struct {
		OpLatencies struct {
			Reads    struct{ Latency, Ops float64 } `bson:"reads"`
			Writes   struct{ Latency, Ops float64 } `bson:"writes"`
			Commands struct{ Latency, Ops float64 } `bson:"commands"`
		} `bson:"opLatencies"`
		WiredTiger struct {
			Cache map[string]float64 `bson:"cache"`
		} `bson:"wiredTiger"`
	}
	if err := admin.RunCommand(ctx, bson.D{{Key: "serverStatus", Value: 1}}).Decode(&status); err != nil {
		return DeepMetricsResult{}, fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
	}
	avgLatencyMs := func(latency, ops float64) (float64, bool) {
		if ops <= 0 {
			return 0, false
		}
		return roundTo(latency/1000/ops, 2), true
	}
	if v, ok := avgLatencyMs(status.OpLatencies.Reads.Latency, status.OpLatencies.Reads.Ops); ok {
		result.Details["avg_read_latency_ms"] = v
	}
	if v, ok := avgLatencyMs(status.OpLatencies.Writes.Latency, status.OpLatencies.Writes.Ops); ok {
		result.Details["avg_write_latency_ms"] = v
	}
	if v, ok := avgLatencyMs(status.OpLatencies.Commands.Latency, status.OpLatencies.Commands.Ops); ok {
		result.Details["avg_command_latency_ms"] = v
	}
	if used, ok := status.WiredTiger.Cache["bytes currently in the cache"]; ok {
		result.Details["wiredtiger_cache_used_bytes"] = int64(used)
	}
	if max, ok := status.WiredTiger.Cache["maximum bytes configured"]; ok {
		result.Details["wiredtiger_cache_max_bytes"] = int64(max)
	}

	var replStatus struct {
		Members []struct {
			StateStr string `bson:"stateStr"`
		} `bson:"members"`
	}
	if err := client.Database("admin").RunCommand(ctx, bson.D{{Key: "replSetGetStatus", Value: 1}}).Decode(&replStatus); err == nil {
		result.Replication.Status = "HEALTHY"
		count := int64(0)
		for _, m := range replStatus.Members {
			if m.StateStr == "SECONDARY" {
				count++
			}
		}
		result.Replication.ReplicaCount = &count
	}
	return result, nil
}

// --- Redis/Valkey ---

func collectRedisDeepDirectly(ctx context.Context, conn DirectDatabaseConnection) (DeepMetricsResult, error) {
	client := redis.NewClient(redisOptions(conn))
	defer client.Close()

	info, err := client.Info(ctx).Result()
	if err != nil {
		return DeepMetricsResult{}, classifyRedisError(err)
	}
	parsed := ParseRedisInfo(info)
	return parseRedisDeepInfo(parsed), nil
}

func parseRedisDeepInfo(info map[string]string) DeepMetricsResult {
	result := DeepMetricsResult{RawCounters: map[string]float64{}, Details: map[string]any{}, Replication: ReplicationDetail{Status: "NOT_CONFIGURED"}}

	if v, ok := redisFloat(info, "evicted_keys"); ok {
		result.RawCounters["evicted_keys"] = v
	}
	if v, ok := redisFloat(info, "expired_keys"); ok {
		result.RawCounters["expired_keys"] = v
	}
	if v, ok := redisFloat(info, "instantaneous_ops_per_sec"); ok {
		result.Details["instantaneous_ops_per_sec"] = v
	}
	if v, ok := redisFloat(info, "mem_fragmentation_ratio"); ok {
		result.Details["mem_fragmentation_ratio"] = v
	}

	replicaCount, hasReplicas := redisInt(info, "connected_slaves")
	if hasReplicas && replicaCount > 0 {
		result.Replication.Status = "HEALTHY"
		result.Replication.ReplicaCount = &replicaCount
		var maxLag float64
		found := false
		for k, v := range info {
			if !strings.HasPrefix(k, "slave") {
				continue
			}
			if m := redisSlaveLinePattern.FindStringSubmatch(v); m != nil {
				if lag, err := strconv.ParseFloat(m[1], 64); err == nil {
					found = true
					if lag > maxLag {
						maxLag = lag
					}
				}
			}
		}
		if found {
			result.Replication.LagSeconds = &maxLag
		}
	} else if role, ok := info["role"]; ok && role == "slave" {
		result.Replication.Status = "HEALTHY"
		if lag, ok := redisFloat(info, "master_last_io_seconds_ago"); ok {
			result.Replication.LagSeconds = &lag
		}
	}

	return result
}
