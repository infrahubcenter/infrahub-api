package services

import "errors"

// DatabaseType identifies a supported standalone database engine. Adding a
// future engine means adding a new constant + a case in direct_database_adapter.go,
// never widening an existing one's behavior.
type DatabaseType string

const (
	DBTypePostgreSQL DatabaseType = "POSTGRESQL"
	DBTypeMySQL      DatabaseType = "MYSQL"
	DBTypeMariaDB    DatabaseType = "MARIADB"
	DBTypeMongoDB    DatabaseType = "MONGODB"
	DBTypeRedis      DatabaseType = "REDIS"
	DBTypeValkey     DatabaseType = "VALKEY"
)

// Typed adapter errors -- callers classify on these rather than parsing
// error strings; the frontend only ever sees the resulting
// connection_status enum, never these Go error values directly.
var (
	ErrDatabaseAuth        = errors.New("database authentication failed")
	ErrDatabaseConnection  = errors.New("database connection refused or unreachable")
	ErrDatabaseTimeout     = errors.New("database connection timed out")
	ErrDatabaseTLS         = errors.New("database TLS handshake failed")
	ErrDatabaseUnsupported = errors.New("database engine not supported")
	// ErrDatabaseQueryFailed means a monitoring query was rejected by an
	// already-established connection (e.g. a column/view this server's
	// version doesn't have) -- distinct from ErrDatabaseConnection, which
	// means the connection itself never succeeded. Conflating the two
	// produced a genuinely misleading "connection refused or unreachable"
	// message for what was actually a schema-compatibility SQL error.
	ErrDatabaseQueryFailed = errors.New("a monitoring query failed")
)

// CommonMetrics is the fast-cycle metrics every engine tries to populate.
// Every field is a pointer/zero-meaning-absent: a metric that couldn't be
// read is simply absent, never a fabricated zero.
type CommonMetrics struct {
	Connections           *int64
	ActiveConnections     *int64
	MaxConnections        *int64
	MemoryUsageBytes      *int64
	DatabaseSizeBytes     *int64
	OperationsPerSecond   *float64
	TransactionsPerSecond *float64
	Errors                *int64
	UptimeSeconds         *int64
}

// MetricsResult is one fast-cycle collection's outcome: the common
// metrics plus an engine-specific detail map, and which of them could
// actually be read. Raw cumulative counters are also returned so the
// collecting service can compute rates without needing the previous
// snapshot itself.
type MetricsResult struct {
	Common  CommonMetrics
	Details map[string]any
	// RawCounters carries cumulative counter values an outer
	// rate-calculation step compares against the previous snapshot's
	// RawCounters -- never itself persisted as a rate.
	RawCounters map[string]float64
	Partial     bool   // true if any optional sub-check failed
	Warning     string // sanitized, human-readable summary of what was skipped
}

// QueryMetric is one query fingerprint's aggregated stats for a single
// deep-metrics collection cycle -- never a copy of every execution, never
// the raw query text unless the caller has DATABASE_QUERY_TEXT_CAPTURE
// enabled (NormalizedText is populated by the adapter regardless; the
// deep metrics service strips/truncates it before persisting based on
// that config flag -- the adapter itself doesn't know about the flag).
type QueryMetric struct {
	Fingerprint    string
	Calls          *int64
	TotalTimeMs    *float64
	AvgTimeMs      *float64
	Rows           *int64
	BlocksRead     *int64
	BlocksHit      *int64
	DatabaseName   string
	DatabaseUser   string
	NormalizedText string
}

// LockMetrics is the current waiting/blocked session counts -- counts
// only; the detailed blocking/blocked pair list (PIDs) lives in Details
// under a documented key, Admin-gated at the handler layer, never used
// to terminate anything.
type LockMetrics struct {
	Waiting *int64
	Blocked *int64
}

// ReplicationDetail is the deep-cycle replication picture: Status
// distinguishes "not configured" from "configured and healthy" from
// "configured and lagging" -- never conflates the two.
type ReplicationDetail struct {
	Status       string // HEALTHY | LAGGING | NOT_CONFIGURED | UNKNOWN
	LagSeconds   *float64
	ReplicaCount *int64
}

// SessionInfo is one currently-active session's non-sensitive facts:
// PID/database/user/duration/state/wait event/application name, and the
// PIDs of any session it's blocked behind -- deliberately never a
// query-text field, by construction (the queries that produce this never
// select one).
type SessionInfo struct {
	PID             int64
	Database        string
	User            string
	DurationSeconds int64
	State           string
	WaitEventType   string
	WaitEvent       string
	ApplicationName string
	// BlockingPIDs is non-empty when this session is blocked waiting on a
	// lock held by another session -- never used to terminate anything,
	// only to display "session X is blocked by session Y."
	BlockingPIDs []string
}

// DeepMetricsResult is one deep-cycle collection's outcome: the
// expensive, less-frequent performance dimensions, deliberately separate
// from the cheap/frequent MetricsResult. Every optional metric a
// particular engine/version doesn't expose is simply absent.
type DeepMetricsResult struct {
	CacheHitRatio    *float64
	Deadlocks        *int64
	CheckpointsTimed *int64
	CheckpointsReq   *int64
	Locks            LockMetrics
	Replication      ReplicationDetail
	Queries          []QueryMetric
	Sessions         []SessionInfo
	// WaitEvents maps a wait_event_type (Lock/IO/Client/LWLock/...) to the
	// number of currently-waiting sessions in that category.
	WaitEvents map[string]int64
	// RawCounters carries cumulative counters (e.g. xact_commit,
	// xact_rollback, temp_files, temp_bytes, wal_lsn_bytes) an outer
	// rate-calculation step compares against the previous deep snapshot's
	// counters to derive a since-last-cycle delta or per-second rate.
	// Never persisted as-is: temp_files/temp_bytes/wal_lsn_bytes are
	// lifetime totals on their own and only become meaningful ("activity
	// this cycle") once diffed against the previous cycle.
	RawCounters map[string]float64
	Details     map[string]any
	Partial     bool
	Warning     string
}
