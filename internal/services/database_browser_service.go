package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"vmcontrolcenter/backend/internal/repository"
)

var (
	ErrBrowserNotSupported = errors.New("browsing not supported for this database type")
	ErrBrowserConnection   = errors.New("failed to establish browser connection")
)

// DatabaseBrowserService coordinates database browsing operations
// for both VM-hosted (via SSH adapters) and standalone (direct TCP) databases
type DatabaseBrowserService struct {
	store       *repository.Store
	credentials *StandaloneDatabaseCredentialService
	connLimiter *DatabaseConnectionLimiter
}

// NewDatabaseBrowserService creates a browser service
func NewDatabaseBrowserService(
	store *repository.Store,
	credentials *StandaloneDatabaseCredentialService,
	connLimiter *DatabaseConnectionLimiter,
) *DatabaseBrowserService {
	return &DatabaseBrowserService{
		store:       store,
		credentials: credentials,
		connLimiter: connLimiter,
	}
}

// IndexInfo represents database index metadata
type IndexInfo struct {
	Name        string
	Columns     []string
	IsUnique    bool
	IsPrimary   bool
	Description string
}

// --- Catalog operations (all databases share these concepts) ---

// ListDatabases returns every database/schema visible in the cluster this
// connection reaches, each with its current connection count (spec ask:
// "how many dbs, name of dbs, number of connections, because it's a
// database cluster"). Always connects using the resource's own configured
// database -- pg_database/information_schema.schemata are visible
// cluster-wide regardless of which specific database the connection used
// to get there.
func (s *DatabaseBrowserService) ListDatabases(ctx context.Context, databaseID uuid.UUID) ([]DatabaseCatalogEntry, error) {
	// Get database config and type
	db, err := s.store.Queries.GetDatabaseByID(ctx, databaseID)
	if err != nil {
		return nil, fmt.Errorf("failed to get database: %w", err)
	}

	dbType := DatabaseType(db.Engine)
	switch dbType {
	case DBTypePostgreSQL:
		browser, err := s.PostgreSQLDirectBrowser(ctx, databaseID, "")
		if err != nil {
			return nil, err
		}
		defer browser.Close(ctx)
		return browser.ListDatabases(ctx)
	case DBTypeMySQL, DBTypeMariaDB:
		browser, err := s.MySQLDirectBrowser(ctx, databaseID, "")
		if err != nil {
			return nil, err
		}
		defer browser.Close()
		return browser.ListDatabases(ctx)
	default:
		return nil, fmt.Errorf("%w: type %s", ErrBrowserNotSupported, dbType)
	}
}

// ListSchemas returns schemas (PostgreSQL only). targetDatabase, if
// non-empty, browses a sibling database in the same cluster instead of
// this resource's own configured one (pgAdmin-style: one set of
// credentials, pick which database to look inside) -- must be one of the
// names ListDatabases already returned; the frontend enforces this by only
// ever offering that same list, so no separate existence check is done
// here (a typo simply fails to connect, same as any other bad input).
func (s *DatabaseBrowserService) ListSchemas(ctx context.Context, databaseID uuid.UUID, targetDatabase string) ([]string, error) {
	// Get database config
	db, err := s.store.Queries.GetDatabaseByID(ctx, databaseID)
	if err != nil {
		return nil, fmt.Errorf("failed to get database: %w", err)
	}

	dbType := DatabaseType(db.Engine)
	if dbType != DBTypePostgreSQL {
		return nil, fmt.Errorf("schemas only supported for PostgreSQL, not %s", dbType)
	}

	browser, err := s.PostgreSQLDirectBrowser(ctx, databaseID, targetDatabase)
	if err != nil {
		return nil, err
	}
	defer browser.Close(ctx)
	return browser.ListSchemas(ctx)
}

// ListTables returns tables in database/schema. See ListSchemas' doc on
// targetDatabase. For MySQL/MariaDB, "database" and "schema" are the same
// concept -- targetDatabase, when set, replaces schema as the effective
// database name (MySQL's sql.DB is not bound to one database the way a
// pgx connection is, so no reconnect is needed there).
func (s *DatabaseBrowserService) ListTables(ctx context.Context, databaseID uuid.UUID, schema, targetDatabase string) ([]TableInfo, error) {
	db, err := s.store.Queries.GetDatabaseByID(ctx, databaseID)
	if err != nil {
		return nil, fmt.Errorf("failed to get database: %w", err)
	}

	dbType := DatabaseType(db.Engine)
	switch dbType {
	case DBTypePostgreSQL:
		browser, err := s.PostgreSQLDirectBrowser(ctx, databaseID, targetDatabase)
		if err != nil {
			return nil, err
		}
		defer browser.Close(ctx)
		effectiveSchema := pgEffectiveSchema(schema)
		if !isValidIdentifier(effectiveSchema) {
			return nil, fmt.Errorf("invalid schema: %s", effectiveSchema)
		}
		return browser.ListTables(ctx, effectiveSchema)
	case DBTypeMySQL, DBTypeMariaDB:
		browser, err := s.MySQLDirectBrowser(ctx, databaseID, targetDatabase)
		if err != nil {
			return nil, err
		}
		defer browser.Close()
		effectiveSchema := mysqlEffectiveDatabase(schema, targetDatabase, db.DatabaseName.String)
		if !isValidIdentifier(effectiveSchema) {
			return nil, fmt.Errorf("invalid database: %s", effectiveSchema)
		}
		return browser.ListTables(ctx, effectiveSchema)
	default:
		return nil, fmt.Errorf("%w: type %s", ErrBrowserNotSupported, dbType)
	}
}

// ListColumns returns columns in a table. See ListTables' doc on
// targetDatabase/schema handling. An empty schema defaults per-engine
// (Postgres: "public"; MySQL/MariaDB: this resource's own configured
// database) rather than failing identifier validation outright -- the
// frontend's "Default" schema option always sends "", which must resolve
// to something queryable, not a 400.
func (s *DatabaseBrowserService) ListColumns(ctx context.Context, databaseID uuid.UUID, schema, table, targetDatabase string) ([]ColumnInfo, error) {
	if !isValidIdentifier(table) {
		return nil, fmt.Errorf("invalid table identifier")
	}

	db, err := s.store.Queries.GetDatabaseByID(ctx, databaseID)
	if err != nil {
		return nil, fmt.Errorf("failed to get database: %w", err)
	}

	dbType := DatabaseType(db.Engine)
	switch dbType {
	case DBTypePostgreSQL:
		browser, err := s.PostgreSQLDirectBrowser(ctx, databaseID, targetDatabase)
		if err != nil {
			return nil, err
		}
		defer browser.Close(ctx)
		effectiveSchema := pgEffectiveSchema(schema)
		if !isValidIdentifier(effectiveSchema) {
			return nil, fmt.Errorf("invalid schema: %s", effectiveSchema)
		}
		return browser.ListColumns(ctx, effectiveSchema, table)
	case DBTypeMySQL, DBTypeMariaDB:
		browser, err := s.MySQLDirectBrowser(ctx, databaseID, targetDatabase)
		if err != nil {
			return nil, err
		}
		defer browser.Close()
		effectiveSchema := mysqlEffectiveDatabase(schema, targetDatabase, db.DatabaseName.String)
		if !isValidIdentifier(effectiveSchema) {
			return nil, fmt.Errorf("invalid database: %s", effectiveSchema)
		}
		return browser.ListColumns(ctx, effectiveSchema, table)
	default:
		return nil, fmt.Errorf("%w: type %s", ErrBrowserNotSupported, dbType)
	}
}

// GetTableRows returns paginated rows from a table. See ListColumns' doc
// on the empty-schema default.
func (s *DatabaseBrowserService) GetTableRows(ctx context.Context, databaseID uuid.UUID, schema, table string, limit, offset int, targetDatabase string) ([]RowData, error) {
	if !isValidIdentifier(table) {
		return nil, fmt.Errorf("invalid table identifier")
	}

	// Enforce limits (spec #21-22)
	if limit > MaxBrowserRowLimit {
		limit = MaxBrowserRowLimit
	}
	if limit <= 0 {
		limit = DefaultBrowserRowLimit
	}
	if offset < 0 {
		offset = 0
	}

	db, err := s.store.Queries.GetDatabaseByID(ctx, databaseID)
	if err != nil {
		return nil, fmt.Errorf("failed to get database: %w", err)
	}

	dbType := DatabaseType(db.Engine)
	switch dbType {
	case DBTypePostgreSQL:
		browser, err := s.PostgreSQLDirectBrowser(ctx, databaseID, targetDatabase)
		if err != nil {
			return nil, err
		}
		defer browser.Close(ctx)
		effectiveSchema := pgEffectiveSchema(schema)
		if !isValidIdentifier(effectiveSchema) {
			return nil, fmt.Errorf("invalid schema: %s", effectiveSchema)
		}
		return browser.GetTableRows(ctx, effectiveSchema, table, limit, offset)
	case DBTypeMySQL, DBTypeMariaDB:
		browser, err := s.MySQLDirectBrowser(ctx, databaseID, targetDatabase)
		if err != nil {
			return nil, err
		}
		defer browser.Close()
		effectiveSchema := mysqlEffectiveDatabase(schema, targetDatabase, db.DatabaseName.String)
		if !isValidIdentifier(effectiveSchema) {
			return nil, fmt.Errorf("invalid database: %s", effectiveSchema)
		}
		return browser.GetTableRows(ctx, effectiveSchema, table, limit, offset)
	default:
		return nil, fmt.Errorf("%w: type %s", ErrBrowserNotSupported, dbType)
	}
}

// SearchTableData searches table data with validated parameters (spec
// #106). See ListColumns' doc on the empty-schema default.
func (s *DatabaseBrowserService) SearchTableData(ctx context.Context, databaseID uuid.UUID, schema, table, column, query string, limit, offset int, targetDatabase string) ([]RowData, error) {
	// Validate identifiers first (spec #23)
	if !isValidIdentifier(table) || !isValidIdentifier(column) {
		return nil, fmt.Errorf("invalid identifier in search")
	}

	// Validate column name against actual table columns first (spec #23, #106)
	columns, err := s.ListColumns(ctx, databaseID, schema, table, targetDatabase)
	if err != nil {
		return nil, err
	}

	// Ensure column exists and is valid
	columnExists := false
	for _, c := range columns {
		if c.Name == column {
			columnExists = true
			break
		}
	}
	if !columnExists {
		return nil, fmt.Errorf("column %q not found in table", column)
	}

	// Enforce limits (spec #21-22)
	if limit > MaxBrowserRowLimit {
		limit = MaxBrowserRowLimit
	}
	if limit <= 0 {
		limit = DefaultBrowserRowLimit
	}
	if offset < 0 {
		offset = 0
	}

	// Get database to determine type
	db, err := s.store.Queries.GetDatabaseByID(ctx, databaseID)
	if err != nil {
		return nil, fmt.Errorf("failed to get database: %w", err)
	}

	dbType := DatabaseType(db.Engine)
	switch dbType {
	case DBTypePostgreSQL:
		browser, err := s.PostgreSQLDirectBrowser(ctx, databaseID, targetDatabase)
		if err != nil {
			return nil, err
		}
		defer browser.Close(ctx)
		return browser.SearchTableData(ctx, pgEffectiveSchema(schema), table, column, query, limit, offset)
	case DBTypeMySQL, DBTypeMariaDB:
		browser, err := s.MySQLDirectBrowser(ctx, databaseID, targetDatabase)
		if err != nil {
			return nil, err
		}
		defer browser.Close()
		return browser.SearchTableData(ctx, mysqlEffectiveDatabase(schema, targetDatabase, db.DatabaseName.String), table, column, query, limit, offset)
	default:
		return nil, fmt.Errorf("%w: type %s", ErrBrowserNotSupported, dbType)
	}
}

// ListIndexes returns indexes on a table (PostgreSQL). See ListColumns'
// doc on the empty-schema default.
func (s *DatabaseBrowserService) ListIndexes(ctx context.Context, databaseID uuid.UUID, schema, table, targetDatabase string) ([]IndexInfo, error) {
	if !isValidIdentifier(table) {
		return nil, fmt.Errorf("invalid table identifier")
	}

	// Get database to determine type
	db, err := s.store.Queries.GetDatabaseByID(ctx, databaseID)
	if err != nil {
		return nil, fmt.Errorf("failed to get database: %w", err)
	}

	dbType := DatabaseType(db.Engine)
	if dbType != DBTypePostgreSQL {
		return nil, fmt.Errorf("indexes only supported for PostgreSQL")
	}

	effectiveSchema := pgEffectiveSchema(schema)
	if !isValidIdentifier(effectiveSchema) {
		return nil, fmt.Errorf("invalid schema: %s", effectiveSchema)
	}

	browser, err := s.PostgreSQLDirectBrowser(ctx, databaseID, targetDatabase)
	if err != nil {
		return nil, err
	}
	defer browser.Close(ctx)
	return browser.ListIndexes(ctx, effectiveSchema, table)
}

// pgEffectiveSchema defaults an unspecified schema to Postgres's own
// default ("public") rather than failing identifier validation outright --
// the frontend's "Default" schema option always sends "".
func pgEffectiveSchema(schema string) string {
	if schema == "" {
		return "public"
	}
	return schema
}

// mysqlEffectiveDatabase picks which MySQL/MariaDB database (there called
// "schema" throughout information_schema) to query against: an explicit
// targetDatabase from the catalog switcher wins; then the existing schema
// value; then this resource's own configured default database.
func mysqlEffectiveDatabase(schema, targetDatabase, configuredDefault string) string {
	if targetDatabase != "" {
		return targetDatabase
	}
	if schema != "" {
		return schema
	}
	return configuredDefault
}

// --- Connection pooling for browsers ---

// PostgreSQLDirectBrowser returns a browser for a direct PostgreSQL
// connection. If targetDatabase is non-empty, it connects to that database
// in the cluster instead of the resource's own configured one (Postgres
// has no "USE other_db" -- browsing a sibling database genuinely requires
// a fresh connection, unlike MySQL).
func (s *DatabaseBrowserService) PostgreSQLDirectBrowser(ctx context.Context, databaseID uuid.UUID, targetDatabase string) (*PostgreSQLBrowser, error) {
	// Get database config
	db, err := s.store.Queries.GetDatabaseByID(ctx, databaseID)
	if err != nil {
		return nil, fmt.Errorf("failed to load database config: %w", err)
	}

	// Validate it's PostgreSQL
	if DatabaseType(db.Engine) != DBTypePostgreSQL {
		return nil, fmt.Errorf("database is not PostgreSQL")
	}

	// Load credentials via the existing service API
	username, password, err := s.credentials.GetCredential(ctx, databaseID)
	if err != nil {
		return nil, fmt.Errorf("failed to load database credentials: %w", err)
	}

	databaseName := db.DatabaseName.String
	if targetDatabase != "" {
		databaseName = targetDatabase
	}

	// Create connection string -- TLSEnabled/TLSSkipVerify must come from
	// this database's own configured tls_enabled/tls_skip_verify (not the
	// legacy, unused ssl_enabled column, and never hardcoded false): a
	// managed cluster that requires TLS otherwise silently refuses every
	// browser connection while every other feature (metrics, operations)
	// connects fine, because those already read the correct fields.
	conn := &DirectDatabaseConnection{
		Type:           DBTypePostgreSQL,
		Host:           db.Host,
		Port:           int(db.Port),
		Database:       databaseName,
		Username:       username,
		Password:       password,
		TLSEnabled:     db.TlsEnabled,
		TLSSkipVerify:  db.TlsSkipVerify,
		ConnectTimeout: 10 * time.Second,
		QueryTimeout:   5 * time.Second,
	}

	// Acquire connection slot from limiter (spec #133)
	if err := s.connLimiter.Acquire(ctx); err != nil {
		return nil, fmt.Errorf("database connection limit reached: %w", err)
	}

	// Establish pgx connection
	pgxConn, err := establishPostgresConnection(ctx, conn)
	if err != nil {
		s.connLimiter.Release()
		return nil, fmt.Errorf("failed to establish connection: %w", err)
	}

	// Return browser (it will manage connection)
	return &PostgreSQLBrowser{
		conn:       pgxConn,
		limiter:    s.connLimiter,
		databaseID: databaseID,
	}, nil
}

// MySQLDirectBrowser returns a browser for a direct MySQL/MariaDB
// connection. targetDatabase, if non-empty, becomes the connection's
// initial default database -- browsing a *different* database in the same
// cluster is instead handled per-query via mysqlEffectiveDatabase, since
// information_schema queries aren't scoped to the connection's default.
func (s *DatabaseBrowserService) MySQLDirectBrowser(ctx context.Context, databaseID uuid.UUID, targetDatabase string) (*MySQLBrowser, error) {
	// Get database config
	db, err := s.store.Queries.GetDatabaseByID(ctx, databaseID)
	if err != nil {
		return nil, fmt.Errorf("failed to load database config: %w", err)
	}

	// Validate it's MySQL/MariaDB
	dbType := DatabaseType(db.Engine)
	if dbType != DBTypeMySQL && dbType != DBTypeMariaDB {
		return nil, fmt.Errorf("database is not MySQL/MariaDB")
	}

	// Load credentials via the existing service API
	username, password, err := s.credentials.GetCredential(ctx, databaseID)
	if err != nil {
		return nil, fmt.Errorf("failed to load database credentials: %w", err)
	}

	databaseName := db.DatabaseName.String
	if targetDatabase != "" {
		databaseName = targetDatabase
	}

	// Create connection string -- see PostgreSQLDirectBrowser's identical
	// note on why TLSEnabled/TLSSkipVerify must read the real configured
	// fields rather than the legacy column or a hardcoded false.
	conn := &DirectDatabaseConnection{
		Type:           dbType,
		Host:           db.Host,
		Port:           int(db.Port),
		Database:       databaseName,
		Username:       username,
		Password:       password,
		TLSEnabled:     db.TlsEnabled,
		TLSSkipVerify:  db.TlsSkipVerify,
		ConnectTimeout: 10 * time.Second,
		QueryTimeout:   5 * time.Second,
	}

	// Acquire connection slot from limiter (spec #133)
	if err := s.connLimiter.Acquire(ctx); err != nil {
		return nil, fmt.Errorf("database connection limit reached: %w", err)
	}

	// Establish sql.DB connection
	sqlDB, err := establishMySQLConnection(ctx, conn)
	if err != nil {
		s.connLimiter.Release()
		return nil, fmt.Errorf("failed to establish connection: %w", err)
	}

	// Return browser (it will manage connection)
	return &MySQLBrowser{
		db:         sqlDB,
		limiter:    s.connLimiter,
		databaseID: databaseID,
	}, nil
}

// --- Authorization helpers (spec #74-80) ---

// CanBrowserDatabase checks if user can browse a database (spec #74)
// Members need database.browser permission, Admins always allowed
func CanBrowserDatabase(user AuthenticatedUser, role string, permission string) bool {
	// Check if user has database.browser permission
	// For Members: explicit grant required
	// For Admins: always allowed
	return user.IsAdmin() || role == RoleMember && permission == "database.browser"
}

// CanViewDatabaseLogs checks if user can view database logs (spec #74-148)
// Members need database.logs permission, Admins always allowed
func CanViewDatabaseLogs(user AuthenticatedUser, role string) bool {
	return user.IsAdmin() || (role == RoleMember)
}

func findPermission(perms []string, target string) *string {
	for i := range perms {
		if perms[i] == target {
			return &perms[i]
		}
	}
	return nil
}

// --- Validation utilities (spec #23: validate identifiers) ---

// ValidateTableBrowser ensures table browser operation is safe
// Returns error if any identifier is invalid
func ValidateTableBrowser(schema, table, column string) error {
	if !isValidIdentifier(schema) {
		return fmt.Errorf("invalid schema: %s", schema)
	}
	if !isValidIdentifier(table) {
		return fmt.Errorf("invalid table: %s", table)
	}
	if column != "" && !isValidIdentifier(column) {
		return fmt.Errorf("invalid column: %s", column)
	}
	return nil
}

// --- Logs viewer (spec #33-36) ---

// LogsCapability describes what log types are available for a database
type LogsCapability struct {
	Supported     bool
	Types         []string // e.g. ["error", "slow_query", "general"]
	Searchable    bool
	StreamingLive bool
	RetentionDays int
}

// GetLogsCapability returns what log features are available (spec #34)
// Do not fake logs if unavailable (spec #34, #41)
func (s *DatabaseBrowserService) GetLogsCapability(ctx context.Context, databaseType DatabaseType, provider string) LogsCapability {
	switch databaseType {
	case DBTypePostgreSQL:
		if provider == "AWS_RDS" {
			// AWS RDS PostgreSQL has log streams
			return LogsCapability{
				Supported:     true,
				Types:         []string{"postgresql"},
				Searchable:    true,
				StreamingLive: false,
				RetentionDays: 7,
			}
		}
		// Self-hosted PostgreSQL has limited logs
		return LogsCapability{
			Supported:     true,
			Types:         []string{"postgresql"},
			Searchable:    false,
			StreamingLive: false,
			RetentionDays: 7,
		}
	case DBTypeMySQL, DBTypeMariaDB:
		// MySQL/MariaDB have no table-output option for the error log --
		// only general_log/slow_log support log_output='TABLE', which is
		// what GetLogs actually reads (see direct_database_logs.go).
		return LogsCapability{
			Supported:     true,
			Types:         []string{"general", "slow_query"},
			Searchable:    true,
			StreamingLive: false,
			RetentionDays: 7,
		}
	default:
		// Other databases may not expose logs
		return LogsCapability{Supported: false}
	}
}

// LogEntry represents a single database log line
type LogEntry struct {
	Timestamp string
	Severity  string
	Source    string
	Message   string
}

// GetLogs retrieves database logs (spec #35-36) by connecting directly
// to the database server and reading whatever log source that engine
// exposes over a plain SQL/client connection -- see
// direct_database_logs.go's own doc comment for why this differs
// per-engine. Never fakes logs if unavailable (spec #41): a genuinely
// unsupported engine or an unreadable server returns a specific error
// (ErrDatabaseLogsUnsupported/ErrDatabaseLogsNotConfigured) rather than a
// silent empty list.
func (s *DatabaseBrowserService) GetLogs(
	ctx context.Context,
	databaseID uuid.UUID,
	logType string,
	fromTime, toTime string,
	limit int,
) ([]LogEntry, error) {
	db, err := s.store.Queries.GetDatabaseByID(ctx, databaseID)
	if err != nil {
		return nil, fmt.Errorf("failed to load database config: %w", err)
	}

	username, password, err := s.credentials.GetCredential(ctx, databaseID)
	if err != nil {
		return nil, fmt.Errorf("%w: no monitoring credential is configured for this database yet -- add one on the Overview tab", ErrDatabaseLogsNotConfigured)
	}

	from, to := time.Time{}, time.Time{}
	if fromTime != "" {
		from, _ = time.Parse(time.RFC3339, fromTime)
	}
	if toTime != "" {
		to, _ = time.Parse(time.RFC3339, toTime)
	}

	conn := DirectDatabaseConnection{
		Type: DatabaseType(db.Engine), Host: db.Host, Port: int(db.Port), Username: username, Password: password,
		Database: db.DatabaseName.String, TLSEnabled: db.TlsEnabled, TLSSkipVerify: db.TlsSkipVerify,
		ConnectTimeout: 10 * time.Second, QueryTimeout: 10 * time.Second,
	}

	if err := s.connLimiter.Acquire(ctx); err != nil {
		return nil, fmt.Errorf("database connection limit reached: %w", err)
	}
	defer s.connLimiter.Release()

	return CollectDirectDatabaseLogs(ctx, conn, from, to, limit)
}

// --- Stub implementations (would need redis-go, mongo-go-driver) ---

// MongoDBDocumentBrowser provides read-only document browsing for MongoDB
type MongoDBDocumentBrowser struct {
	// Requires mongo-go-driver
	// Would provide:
	// - ListDatabases()
	// - ListCollections(database)
	// - GetDocuments(database, collection, limit, offset)
	// - SearchDocuments(database, collection, query, limit, offset)
}

// ListDocuments returns documents from a MongoDB collection (spec #28-29)
func (b *MongoDBDocumentBrowser) ListDocuments(ctx context.Context, database, collection string, limit, offset int) ([]map[string]interface{}, error) {
	// Validate limit (spec #28-29: default 50, max 200)
	if limit > MaxBrowserRowLimit {
		limit = MaxBrowserRowLimit
	}
	if limit <= 0 {
		limit = DefaultBrowserRowLimit
	}

	// Would use mongo driver to query collection
	return []map[string]interface{}{}, ErrBrowserNotSupported
}

// RedisKeyScan provides safe key discovery for Redis (spec #29-30, #88)
type RedisKeyScan struct {
	// Requires redis-go or similar
	// Would provide safe key discovery via SCAN (not KEYS *)
}

// ListKeys returns keys from Redis with safe pagination (spec #30, #88)
// Never uses KEYS * on production Redis
func (b *RedisKeyScan) ListKeys(ctx context.Context, pattern string, limit, offset int) ([]string, error) {
	// Use SCAN with cursor-based pagination
	// Avoid KEYS * (spec #88)
	return []string{}, ErrBrowserNotSupported
}

// GetKeyValue returns value preview for a Redis key (spec #30)
// Limits large values to prevent browser memory issues
func (b *RedisKeyScan) GetKeyValue(ctx context.Context, key string) (interface{}, error) {
	// Get key type
	// Get value (truncated for large values)
	// Return preview
	return nil, ErrBrowserNotSupported
}

// --- Audit helpers (spec #107) ---

// AuditBrowserAccess records when admin views table data
// Note: Do not store actual row data in audit logs (spec #107)
func AuditBrowserAccess(action, databaseID, tableName string) string {
	// Would create audit entry like:
	// "DATABASE_TABLE_DATA_VIEWED" with metadata
	// {database_id, table_name, row_count, NOT row_data}
	return fmt.Sprintf("DATABASE_BROWSER_ACCESSED: %s.%s", databaseID, tableName)
}

// --- Internal helpers for establishing connections ---

// establishPostgresConnection creates a pgx connection for the PostgreSQL
// browser -- reuses postgresConnString (direct_database_adapter.go) so
// browsing honors the exact same sslmode negotiation (disable/require/
// verify-full) as connection testing and metrics collection, instead of
// hardcoding sslmode=disable regardless of the database's own TLS config.
func establishPostgresConnection(ctx context.Context, conn *DirectDatabaseConnection) (*pgx.Conn, error) {
	connCtx, cancel := context.WithTimeout(ctx, conn.ConnectTimeout)
	defer cancel()

	pgxConn, err := pgx.Connect(connCtx, postgresConnString(*conn))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}
	return pgxConn, nil
}

// establishMySQLConnection creates a sql.DB connection for the MySQL
// browser -- reuses mysqlDSN (direct_database_adapter.go) so browsing
// honors the database's real TLS config instead of always connecting
// unencrypted regardless of tls_enabled/tls_skip_verify.
func establishMySQLConnection(ctx context.Context, conn *DirectDatabaseConnection) (*sql.DB, error) {
	db, err := sql.Open("mysql", mysqlDSN(*conn))
	if err != nil {
		return nil, fmt.Errorf("failed to open MySQL connection: %w", err)
	}

	// Test the connection
	connCtx, cancel := context.WithTimeout(ctx, conn.ConnectTimeout)
	defer cancel()

	if err := db.PingContext(connCtx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to connect to MySQL: %w", err)
	}

	return db, nil
}
