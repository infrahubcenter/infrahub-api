package services

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	pgconnpkg "github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// DirectDatabaseConnection represents a direct TCP/TLS connection to a
// standalone database -- every standalone engine is reached this way
// (spec §2: "Do NOT require SSH"), via each engine's own official Go
// driver (pgx, go-sql-driver/mysql, mongo-driver, go-redis), never a
// second, hand-rolled protocol implementation.
type DirectDatabaseConnection struct {
	Type           DatabaseType
	Host           string
	Port           int
	Username       string
	Password       string
	Database       string
	TLSEnabled     bool
	TLSSkipVerify  bool
	ConnectTimeout time.Duration
	QueryTimeout   time.Duration
}

// TestDirectConnection tests a direct TCP/TLS connection to a standalone
// database and runs exactly one backend-defined, read-only health-check
// call -- never a client-supplied query/command of any kind.
func TestDirectConnection(ctx context.Context, conn DirectDatabaseConnection) error {
	ctx, cancel := context.WithTimeout(ctx, conn.ConnectTimeout)
	defer cancel()

	switch conn.Type {
	case DBTypePostgreSQL:
		return testPostgresDirectConnection(ctx, conn)
	case DBTypeMySQL, DBTypeMariaDB:
		return testMySQLDirectConnection(ctx, conn)
	case DBTypeMongoDB:
		return testMongoDBDirectConnection(ctx, conn)
	case DBTypeRedis, DBTypeValkey:
		return testRedisDirectConnection(ctx, conn)
	default:
		return fmt.Errorf("%w: %s", ErrDatabaseUnsupported, conn.Type)
	}
}

func classifyPgError(err error) error {
	if pgErr, ok := err.(*pgconnpkg.PgError); ok {
		if pgErr.Code == "28P01" || pgErr.Code == "28000" {
			return fmt.Errorf("%w: %s", ErrDatabaseAuth, pgErr.Message)
		}
	}
	return fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
}

func postgresConnString(conn DirectDatabaseConnection) string {
	sslmode := "disable"
	if conn.TLSEnabled {
		if conn.TLSSkipVerify {
			sslmode = "require" // pgx: "require" encrypts without verifying CA, matching TLSSkipVerify's intent
		} else {
			sslmode = "verify-full"
		}
	}
	dbName := conn.Database
	if dbName == "" {
		dbName = "postgres"
	}
	// Built via net/url (not fmt.Sprintf) so a username/password containing
	// "@", ":", "/", or "%" is percent-encoded rather than corrupting the
	// URL -- unescaped, such a password could silently truncate the
	// Username/Password pgx parses back out, or be misread as part of the
	// host, mirroring the same class of bug mongoConnString's
	// mongoURIEscape already guards against.
	// Built via net/url (not fmt.Sprintf) so a username/password containing
	// "@", ":", "/", or "%" is percent-encoded rather than corrupting the
	// URL -- unescaped, such a password could silently truncate the
	// Username/Password pgx parses back out, or be misread as part of the
	// host, mirroring the same class of bug mongoConnString's
	// mongoURIEscape already guards against.
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(conn.Username, conn.Password),
		Host:     fmt.Sprintf("%s:%d", conn.Host, conn.Port),
		Path:     "/" + dbName,
		RawQuery: "sslmode=" + sslmode,
	}
	return u.String()
}

func testPostgresDirectConnection(ctx context.Context, conn DirectDatabaseConnection) error {
	pgxConn, err := pgx.Connect(ctx, postgresConnString(conn))
	if err != nil {
		return classifyPgError(err)
	}
	defer pgxConn.Close(ctx)

	var result int
	if err := pgxConn.QueryRow(ctx, "SELECT 1").Scan(&result); err != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
	}
	return nil
}

// mysqlDSN builds the DSN via the driver's own mysql.Config/FormatDSN
// (not fmt.Sprintf) so a username/password containing "@", ":", or "/"
// is correctly quoted rather than corrupting the "user:pass@tcp(host:port)"
// shape -- the same class of bug postgresConnString's net/url construction
// and mongoConnString's mongoURIEscape both already guard against.
func mysqlDSN(conn DirectDatabaseConnection) string {
	cfg := mysql.NewConfig()
	cfg.User = conn.Username
	cfg.Passwd = conn.Password
	cfg.Net = "tcp"
	cfg.Addr = fmt.Sprintf("%s:%d", conn.Host, conn.Port)
	cfg.DBName = conn.Database
	cfg.Timeout = conn.ConnectTimeout
	if conn.TLSEnabled {
		if conn.TLSSkipVerify {
			cfg.TLSConfig = "skip-verify"
		} else {
			cfg.TLSConfig = "true"
		}
	}
	return cfg.FormatDSN()
}

func classifyMySQLError(err error) error {
	msg := err.Error()
	switch {
	case containsAny(msg, "Access denied"):
		return fmt.Errorf("%w: %v", ErrDatabaseAuth, err)
	case containsAny(msg, "i/o timeout", "context deadline exceeded"):
		return fmt.Errorf("%w: %v", ErrDatabaseTimeout, err)
	default:
		return fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

func mysqlOpen(conn DirectDatabaseConnection) (*sql.DB, error) {
	db, err := sql.Open("mysql", mysqlDSN(conn))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
	}
	return db, nil
}

func testMySQLDirectConnection(ctx context.Context, conn DirectDatabaseConnection) error {
	db, err := mysqlOpen(conn)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return classifyMySQLError(err)
	}
	return nil
}

func mongoConnString(conn DirectDatabaseConnection) string {
	scheme := "mongodb"
	tlsParam := ""
	if conn.TLSEnabled {
		tlsParam = "&tls=true"
		if conn.TLSSkipVerify {
			tlsParam += "&tlsInsecure=true"
		}
	}
	auth := ""
	if conn.Username != "" {
		auth = fmt.Sprintf("%s:%s@", mongoURIEscape(conn.Username), mongoURIEscape(conn.Password))
	}
	return fmt.Sprintf("%s://%s%s:%d/?authSource=admin%s", scheme, auth, conn.Host, conn.Port, tlsParam)
}

func mongoConnect(ctx context.Context, conn DirectDatabaseConnection) (*mongo.Client, error) {
	opts := options.Client().ApplyURI(mongoConnString(conn)).SetConnectTimeout(conn.ConnectTimeout).SetServerSelectionTimeout(conn.ConnectTimeout)
	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
	}
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		_ = client.Disconnect(ctx)
		msg := err.Error()
		if containsAny(msg, "Authentication failed", "auth error") {
			return nil, fmt.Errorf("%w: %v", ErrDatabaseAuth, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
	}
	return client, nil
}

func testMongoDBDirectConnection(ctx context.Context, conn DirectDatabaseConnection) error {
	client, err := mongoConnect(ctx, conn)
	if err != nil {
		return err
	}
	defer client.Disconnect(ctx)
	return nil
}

func redisOptions(conn DirectDatabaseConnection) *redis.Options {
	opts := &redis.Options{
		Addr:        fmt.Sprintf("%s:%d", conn.Host, conn.Port),
		Password:    conn.Password,
		DialTimeout: conn.ConnectTimeout,
		ReadTimeout: conn.QueryTimeout,
	}
	if conn.TLSEnabled {
		opts.TLSConfig = &tls.Config{InsecureSkipVerify: conn.TLSSkipVerify} //nolint:gosec // admin-controlled, explicit opt-in per instance
	}
	return opts
}

func classifyRedisError(err error) error {
	msg := err.Error()
	switch {
	case containsAny(msg, "NOAUTH", "WRONGPASS", "invalid password"):
		return fmt.Errorf("%w: %v", ErrDatabaseAuth, err)
	case containsAny(msg, "i/o timeout", "context deadline exceeded"):
		return fmt.Errorf("%w: %v", ErrDatabaseTimeout, err)
	default:
		return fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
	}
}

func testRedisDirectConnection(ctx context.Context, conn DirectDatabaseConnection) error {
	client := redis.NewClient(redisOptions(conn))
	defer client.Close()

	if err := client.Ping(ctx).Err(); err != nil {
		return classifyRedisError(err)
	}
	return nil
}

// --- Fast-cycle metrics collection ---

// CollectDirectDatabaseMetrics collects the fast/common metrics from a
// standalone database via its direct connection -- one connect, one
// backend-defined read-only query/command per engine, never a
// client-supplied one.
func CollectDirectDatabaseMetrics(ctx context.Context, conn DirectDatabaseConnection) (MetricsResult, error) {
	ctx, cancel := context.WithTimeout(ctx, conn.QueryTimeout)
	defer cancel()

	switch conn.Type {
	case DBTypePostgreSQL:
		return collectPostgresMetricsDirectly(ctx, conn)
	case DBTypeMySQL, DBTypeMariaDB:
		return collectMySQLMetricsDirectly(ctx, conn)
	case DBTypeMongoDB:
		return collectMongoMetricsDirectly(ctx, conn)
	case DBTypeRedis, DBTypeValkey:
		return collectRedisMetricsDirectly(ctx, conn)
	default:
		return MetricsResult{}, fmt.Errorf("%w: %s", ErrDatabaseUnsupported, conn.Type)
	}
}

const pgCombinedFastQuery = `SELECT ` +
	`(SELECT count(*) FROM pg_stat_activity), ` +
	`(SELECT count(*) FROM pg_stat_activity WHERE state = 'active'), ` +
	`(SELECT setting::bigint FROM pg_settings WHERE name = 'max_connections'), ` +
	`(SELECT extract(epoch FROM now() - pg_postmaster_start_time())::bigint), ` +
	`(SELECT pg_database_size(current_database())), ` +
	`(SELECT sum(xact_commit) FROM pg_stat_database), ` +
	`(SELECT sum(xact_rollback) FROM pg_stat_database)`

func collectPostgresMetricsDirectly(ctx context.Context, conn DirectDatabaseConnection) (MetricsResult, error) {
	pgxConn, err := pgx.Connect(ctx, postgresConnString(conn))
	if err != nil {
		return MetricsResult{}, classifyPgError(err)
	}
	defer pgxConn.Close(ctx)

	m := MetricsResult{Details: map[string]any{}, RawCounters: map[string]float64{}}
	var connections, active, maxConn, uptime, dbSize int64
	var xactCommit, xactRollback *int64
	err = pgxConn.QueryRow(ctx, pgCombinedFastQuery).Scan(&connections, &active, &maxConn, &uptime, &dbSize, &xactCommit, &xactRollback)
	if err != nil {
		return MetricsResult{}, fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
	}
	m.Common.Connections = &connections
	m.Common.ActiveConnections = &active
	m.Common.MaxConnections = &maxConn
	m.Common.UptimeSeconds = &uptime
	m.Common.DatabaseSizeBytes = &dbSize
	if xactCommit != nil {
		m.RawCounters["xact_commit"] = float64(*xactCommit)
	}
	if xactRollback != nil {
		m.RawCounters["xact_rollback"] = float64(*xactRollback)
	}
	return m, nil
}

const mysqlCombinedFastQuery = "SELECT " +
	"(SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='THREADS_CONNECTED'), " +
	"(SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME='MAX_CONNECTIONS'), " +
	"(SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='UPTIME'), " +
	"(SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='QUERIES'), " +
	"(SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='COM_COMMIT'), " +
	"(SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='COM_ROLLBACK'), " +
	"(SELECT ROUND(SUM(DATA_LENGTH+INDEX_LENGTH)) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE())"

func collectMySQLMetricsDirectly(ctx context.Context, conn DirectDatabaseConnection) (MetricsResult, error) {
	db, err := mysqlOpen(conn)
	if err != nil {
		return MetricsResult{}, err
	}
	defer db.Close()

	m := MetricsResult{Details: map[string]any{}, RawCounters: map[string]float64{}}
	var connections, maxConn, uptime string
	var queries, comCommit, comRollback *string
	var dbSize *int64
	row := db.QueryRowContext(ctx, mysqlCombinedFastQuery)
	if err := row.Scan(&connections, &maxConn, &uptime, &queries, &comCommit, &comRollback, &dbSize); err != nil {
		return MetricsResult{}, classifyMySQLError(err)
	}
	if v, err := strconv.ParseInt(connections, 10, 64); err == nil {
		m.Common.Connections = &v
	}
	if v, err := strconv.ParseInt(maxConn, 10, 64); err == nil {
		m.Common.MaxConnections = &v
	}
	if v, err := strconv.ParseInt(uptime, 10, 64); err == nil {
		m.Common.UptimeSeconds = &v
	}
	if dbSize != nil {
		m.Common.DatabaseSizeBytes = dbSize
	}
	if queries != nil {
		if v, err := strconv.ParseFloat(*queries, 64); err == nil {
			m.RawCounters["queries"] = v
		}
	}
	if comCommit != nil {
		if v, err := strconv.ParseFloat(*comCommit, 64); err == nil {
			m.RawCounters["com_commit"] = v
		}
	}
	if comRollback != nil {
		if v, err := strconv.ParseFloat(*comRollback, 64); err == nil {
			m.RawCounters["com_rollback"] = v
		}
	}
	return m, nil
}

func collectMongoMetricsDirectly(ctx context.Context, conn DirectDatabaseConnection) (MetricsResult, error) {
	client, err := mongoConnect(ctx, conn)
	if err != nil {
		return MetricsResult{}, err
	}
	defer client.Disconnect(ctx)

	m := MetricsResult{Details: map[string]any{}, RawCounters: map[string]float64{}}
	admin := client.Database("admin")

	var status struct {
		Connections struct {
			Current   int64 `bson:"current"`
			Available int64 `bson:"available"`
		} `bson:"connections"`
		Mem struct {
			Resident int64 `bson:"resident"`
		} `bson:"mem"`
		Uptime     float64 `bson:"uptime"`
		OpCounters struct {
			Insert  float64 `bson:"insert"`
			Query   float64 `bson:"query"`
			Update  float64 `bson:"update"`
			Delete  float64 `bson:"delete"`
			GetMore float64 `bson:"getmore"`
			Command float64 `bson:"command"`
		} `bson:"opcounters"`
	}
	if err := admin.RunCommand(ctx, bson.D{{Key: "serverStatus", Value: 1}}).Decode(&status); err != nil {
		return MetricsResult{}, fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
	}

	current := status.Connections.Current
	m.Common.Connections = &current
	uptime := int64(status.Uptime)
	m.Common.UptimeSeconds = &uptime
	memBytes := status.Mem.Resident * 1024 * 1024
	m.Common.MemoryUsageBytes = &memBytes
	m.Details["available_connections"] = status.Connections.Available
	m.RawCounters["op_insert"] = status.OpCounters.Insert
	m.RawCounters["op_query"] = status.OpCounters.Query
	m.RawCounters["op_update"] = status.OpCounters.Update
	m.RawCounters["op_delete"] = status.OpCounters.Delete
	m.RawCounters["op_getmore"] = status.OpCounters.GetMore
	m.RawCounters["op_command"] = status.OpCounters.Command

	var dbStats struct {
		TotalSize int64 `bson:"totalSize"`
	}
	if err := admin.RunCommand(ctx, bson.D{{Key: "listDatabases", Value: 1}, {Key: "nameOnly", Value: false}}).Decode(&dbStats); err == nil {
		m.Common.DatabaseSizeBytes = &dbStats.TotalSize
	} else {
		m.Partial = true
		m.Warning = "database size unavailable"
	}
	return m, nil
}

func collectRedisMetricsDirectly(ctx context.Context, conn DirectDatabaseConnection) (MetricsResult, error) {
	client := redis.NewClient(redisOptions(conn))
	defer client.Close()

	info, err := client.Info(ctx).Result()
	if err != nil {
		return MetricsResult{}, classifyRedisError(err)
	}
	parsed := ParseRedisInfo(info)
	return ParseRedisMetrics(parsed), nil
}
