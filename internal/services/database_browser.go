package services

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Database browser constants (spec #21-22)
const (
	DefaultBrowserRowLimit = 50
	MaxBrowserRowLimit     = 200
	BrowserPageSize        = 50
)

// PostgreSQLBrowser implements read-only database browsing for PostgreSQL
type PostgreSQLBrowser struct {
	conn       *pgx.Conn
	limiter    *DatabaseConnectionLimiter
	databaseID uuid.UUID
}

// NewPostgreSQLBrowser creates a browser for PostgreSQL
func NewPostgreSQLBrowser(conn *pgx.Conn) *PostgreSQLBrowser {
	return &PostgreSQLBrowser{conn: conn}
}

// Close releases the real connection and the connection-limiter slot it
// holds. Every DatabaseBrowserService method that obtains a browser must
// defer this -- without it, each browser request page-load permanently
// leaked one live Postgres backend connection (see the service file's
// call sites; this was previously never called at all).
func (b *PostgreSQLBrowser) Close(ctx context.Context) {
	if b.conn != nil {
		_ = b.conn.Close(ctx)
	}
	if b.limiter != nil {
		b.limiter.Release()
	}
}

// DatabaseCatalogEntry is one database/schema visible in the cluster this
// connection is attached to, alongside how many live backend connections
// currently target it (spec ask: "how many dbs, name of dbs, number of
// connections, because it's a database cluster").
type DatabaseCatalogEntry struct {
	Name            string
	ConnectionCount int64
}

// --- Metadata queries (whitelisted, safe) ---

// ListDatabases returns every non-template database in the cluster this
// connection is attached to, with its current connection count.
// pg_stat_activity's datname/pid columns are visible to any role for every
// backend (only the query text itself is redacted without
// pg_read_all_stats) -- no elevated privilege is required for this count.
func (b *PostgreSQLBrowser) ListDatabases(ctx context.Context) ([]DatabaseCatalogEntry, error) {
	rows, err := b.conn.Query(ctx, `
		SELECT d.datname, COALESCE(a.conn_count, 0)
		FROM pg_database d
		LEFT JOIN (
			SELECT datname, count(*) AS conn_count FROM pg_stat_activity GROUP BY datname
		) a ON a.datname = d.datname
		WHERE NOT d.datistemplate
		ORDER BY d.datname
	`)
	if err != nil {
		return nil, fmt.Errorf("list databases failed: %w", err)
	}
	defer rows.Close()

	var databases []DatabaseCatalogEntry
	for rows.Next() {
		var entry DatabaseCatalogEntry
		if err := rows.Scan(&entry.Name, &entry.ConnectionCount); err != nil {
			return nil, err
		}
		databases = append(databases, entry)
	}
	return databases, rows.Err()
}

// ListSchemas returns all schemas in current database (spec #19)
func (b *PostgreSQLBrowser) ListSchemas(ctx context.Context) ([]string, error) {
	rows, err := b.conn.Query(ctx, `
		SELECT schema_name FROM information_schema.schemata
		WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_temp', 'pg_toast')
		ORDER BY schema_name
	`)
	if err != nil {
		return nil, fmt.Errorf("list schemas failed: %w", err)
	}
	defer rows.Close()

	var schemas []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		schemas = append(schemas, name)
	}
	return schemas, rows.Err()
}

// TableInfo holds metadata about a table
type TableInfo struct {
	Schema      string
	Name        string
	RowCount    int64
	SizeBytes   int64
	Description string
}

// ListTables returns tables in a schema (spec #19)
// Whitelist schema input to prevent injection
func (b *PostgreSQLBrowser) ListTables(ctx context.Context, schema string) ([]TableInfo, error) {
	// Validate schema name (spec #23: whitelist before generating queries)
	if !isValidIdentifier(schema) {
		return nil, fmt.Errorf("invalid schema name: %s", schema)
	}

	rows, err := b.conn.Query(ctx, fmt.Sprintf(`
		SELECT
			t.table_schema,
			t.table_name,
			(SELECT n_live_tup FROM pg_stat_user_tables
			 WHERE relname = t.table_name AND schemaname = t.table_schema) AS row_count,
			pg_total_relation_size(t.table_schema||'.'||t.table_name)::bigint AS size_bytes,
			obj_description(('"%s"."'||t.table_name||'"')::regclass, 'pg_class') AS description
		FROM information_schema.tables t
		WHERE t.table_schema = '%s'
		AND t.table_type = 'BASE TABLE'
		ORDER BY t.table_name
	`, schema, schema))
	if err != nil {
		return nil, fmt.Errorf("list tables failed: %w", err)
	}
	defer rows.Close()

	var tables []TableInfo
	for rows.Next() {
		var t TableInfo
		var rowCount, sizeBytes sql.NullInt64
		var desc sql.NullString
		err := rows.Scan(&t.Schema, &t.Name, &rowCount, &sizeBytes, &desc)
		if err != nil {
			return nil, err
		}
		if rowCount.Valid {
			t.RowCount = rowCount.Int64
		}
		if sizeBytes.Valid {
			t.SizeBytes = sizeBytes.Int64
		}
		if desc.Valid {
			t.Description = desc.String
		}
		tables = append(tables, t)
	}
	return tables, rows.Err()
}

// ColumnInfo holds metadata about a table column
type ColumnInfo struct {
	Name     string
	Type     string
	Nullable bool
	Default  string
	Comment  string
}

// ListColumns returns columns in a table (spec #19)
func (b *PostgreSQLBrowser) ListColumns(ctx context.Context, schema, table string) ([]ColumnInfo, error) {
	if !isValidIdentifier(schema) || !isValidIdentifier(table) {
		return nil, fmt.Errorf("invalid schema or table name")
	}

	rows, err := b.conn.Query(ctx, fmt.Sprintf(`
		SELECT
			column_name,
			data_type,
			is_nullable = 'YES' AS nullable,
			column_default,
			col_description(('%s.%s'::regclass)::oid, ordinal_position) AS comment
		FROM information_schema.columns
		WHERE table_schema = '%s' AND table_name = '%s'
		ORDER BY ordinal_position
	`, schema, table, schema, table))
	if err != nil {
		return nil, fmt.Errorf("list columns failed: %w", err)
	}
	defer rows.Close()

	var columns []ColumnInfo
	for rows.Next() {
		var c ColumnInfo
		var defaultVal, comment sql.NullString
		err := rows.Scan(&c.Name, &c.Type, &c.Nullable, &defaultVal, &comment)
		if err != nil {
			return nil, err
		}
		if defaultVal.Valid {
			c.Default = defaultVal.String
		}
		if comment.Valid {
			c.Comment = comment.String
		}
		columns = append(columns, c)
	}
	return columns, rows.Err()
}

// RowData represents a single row of table data
type RowData struct {
	Values map[string]interface{}
}

// GetTableRows returns paginated rows from a table (spec #20-22)
// Uses parameterized queries to prevent injection
func (b *PostgreSQLBrowser) GetTableRows(ctx context.Context, schema, table string, limit, offset int) ([]RowData, error) {
	if !isValidIdentifier(schema) || !isValidIdentifier(table) {
		return nil, fmt.Errorf("invalid schema or table name")
	}

	// Enforce row limit (spec #22)
	if limit > MaxBrowserRowLimit {
		limit = MaxBrowserRowLimit
	}
	if limit <= 0 {
		limit = DefaultBrowserRowLimit
	}

	// Query with parameterized limit/offset. Ordered by ctid (physical
	// row location, always present) rather than oid -- WITH OIDS was
	// removed in Postgres 12 (2019), so "ORDER BY oid" 500s on every
	// modern table; ctid gives the same rough "recently written first"
	// ordering without depending on a column that no longer exists.
	queryStr := fmt.Sprintf(`SELECT * FROM "%s"."%s" ORDER BY ctid DESC LIMIT $1 OFFSET $2`, schema, table)
	rows, err := b.conn.Query(ctx, queryStr, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("query table rows failed: %w", err)
	}
	defer rows.Close()

	var result []RowData
	columns := rows.FieldDescriptions()

	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return nil, err
		}

		rowData := RowData{Values: make(map[string]interface{})}
		for i, col := range columns {
			rowData.Values[string(col.Name)] = values[i]
		}
		result = append(result, rowData)
	}

	return result, rows.Err()
}

// SearchTableData searches table data with a validated column/value filter.
func (b *PostgreSQLBrowser) SearchTableData(ctx context.Context, schema, table, column, query string, limit, offset int) ([]RowData, error) {
	if !isValidIdentifier(schema) || !isValidIdentifier(table) || !isValidIdentifier(column) {
		return nil, fmt.Errorf("invalid schema/table/column name")
	}
	if limit <= 0 {
		limit = DefaultBrowserRowLimit
	}
	if limit > MaxBrowserRowLimit {
		limit = MaxBrowserRowLimit
	}
	if offset < 0 {
		offset = 0
	}

	// See GetTableRows' note on ctid vs. the removed oid column.
	q := fmt.Sprintf(`SELECT * FROM "%s"."%s" WHERE "%s"::text ILIKE $1 ORDER BY ctid DESC LIMIT $2 OFFSET $3`, schema, table, column)
	rows, err := b.conn.Query(ctx, q, "%"+query+"%", limit, offset)
	if err != nil {
		return nil, fmt.Errorf("search table data failed: %w", err)
	}
	defer rows.Close()

	var result []RowData
	fieldNames := rows.FieldDescriptions()
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return nil, err
		}
		rowData := RowData{Values: make(map[string]interface{})}
		for i, fd := range fieldNames {
			rowData.Values[string(fd.Name)] = values[i]
		}
		result = append(result, rowData)
	}
	return result, rows.Err()
}

// ListIndexes returns the indexes for a table. idx_scan/indisunique/
// indisprimary aren't columns of pg_indexes itself (it only has
// schemaname/tablename/indexname/tablespace/indexdef) -- they live on
// pg_stat_user_indexes and pg_index respectively, joined in here via the
// index's own pg_class row. schema/table pass as bind params since they're
// filter values, not identifiers being interpolated into the query shape.
func (b *PostgreSQLBrowser) ListIndexes(ctx context.Context, schema, table string) ([]IndexInfo, error) {
	if !isValidIdentifier(schema) || !isValidIdentifier(table) {
		return nil, fmt.Errorf("invalid schema or table name")
	}

	const query = `
		SELECT
			i.indexname,
			i.indexdef,
			COALESCE(s.idx_scan, 0) AS idx_scan,
			ix.indisunique,
			ix.indisprimary
		FROM pg_indexes i
		JOIN pg_namespace n ON n.nspname = i.schemaname
		JOIN pg_class c ON c.relname = i.indexname AND c.relnamespace = n.oid
		JOIN pg_index ix ON ix.indexrelid = c.oid
		LEFT JOIN pg_stat_user_indexes s ON s.indexrelname = i.indexname AND s.schemaname = i.schemaname
		WHERE i.schemaname = $1 AND i.tablename = $2
		ORDER BY i.indexname
	`

	rows, err := b.conn.Query(ctx, query, schema, table)
	if err != nil {
		return nil, fmt.Errorf("list indexes failed: %w", err)
	}
	defer rows.Close()

	var indexes []IndexInfo
	for rows.Next() {
		var name, indexdef string
		var scanCount int64
		var isUnique, isPrimary bool
		if err := rows.Scan(&name, &indexdef, &scanCount, &isUnique, &isPrimary); err != nil {
			return nil, err
		}
		index := IndexInfo{Name: name, Columns: []string{}, IsUnique: isUnique, IsPrimary: isPrimary}
		if idx := strings.Index(indexdef, "("); idx >= 0 {
			cols := strings.TrimSuffix(strings.TrimPrefix(indexdef[strings.Index(indexdef, "(")+1:], ""), ")")
			index.Columns = []string{cols}
		}
		indexes = append(indexes, index)
	}
	return indexes, rows.Err()
}

// --- MySQL/MariaDB Browser ---

// MySQLBrowser implements read-only database browsing for MySQL/MariaDB
type MySQLBrowser struct {
	db         *sql.DB
	limiter    *DatabaseConnectionLimiter
	databaseID uuid.UUID
}

// NewMySQLBrowser creates a browser for MySQL
func NewMySQLBrowser(db *sql.DB) *MySQLBrowser {
	return &MySQLBrowser{db: db}
}

// Close releases the real connection and the connection-limiter slot it
// holds -- see PostgreSQLBrowser.Close's identical rationale.
func (b *MySQLBrowser) Close() {
	if b.db != nil {
		_ = b.db.Close()
	}
	if b.limiter != nil {
		b.limiter.Release()
	}
}

// ListDatabases returns all accessible databases (MySQL/MariaDB conflate
// "database" and "schema") with a best-effort connection count per
// database. Counting via information_schema.processlist requires the
// PROCESS privilege, which not every configured credential is guaranteed
// to have -- a failure there degrades to "0 known connections" rather than
// failing the whole catalog listing.
func (b *MySQLBrowser) ListDatabases(ctx context.Context) ([]DatabaseCatalogEntry, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT schema_name FROM information_schema.schemata
		WHERE schema_name NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
		ORDER BY schema_name
	`)
	if err != nil {
		return nil, fmt.Errorf("list databases failed: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	counts := map[string]int64{}
	if countRows, countErr := b.db.QueryContext(ctx, `
		SELECT db, COUNT(*) FROM information_schema.processlist WHERE db IS NOT NULL GROUP BY db
	`); countErr == nil {
		for countRows.Next() {
			var dbName string
			var count int64
			if countRows.Scan(&dbName, &count) == nil {
				counts[dbName] = count
			}
		}
		countRows.Close()
	}

	entries := make([]DatabaseCatalogEntry, len(names))
	for i, name := range names {
		entries[i] = DatabaseCatalogEntry{Name: name, ConnectionCount: counts[name]}
	}
	return entries, nil
}

// ListTables returns tables in a database (MySQL)
func (b *MySQLBrowser) ListTables(ctx context.Context, database string) ([]TableInfo, error) {
	if !isValidIdentifier(database) {
		return nil, fmt.Errorf("invalid database name")
	}

	rows, err := b.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT
			'%s' AS table_schema,
			table_name,
			table_rows,
			data_length + index_length AS size_bytes,
			table_comment
		FROM information_schema.tables
		WHERE table_schema = '%s' AND table_type = 'BASE TABLE'
		ORDER BY table_name
	`, database, database))
	if err != nil {
		return nil, fmt.Errorf("list tables failed: %w", err)
	}
	defer rows.Close()

	var tables []TableInfo
	for rows.Next() {
		var t TableInfo
		var rowCount, sizeBytes sql.NullInt64
		var comment sql.NullString
		err := rows.Scan(&t.Schema, &t.Name, &rowCount, &sizeBytes, &comment)
		if err != nil {
			return nil, err
		}
		if rowCount.Valid {
			t.RowCount = rowCount.Int64
		}
		if sizeBytes.Valid {
			t.SizeBytes = sizeBytes.Int64
		}
		if comment.Valid {
			t.Description = comment.String
		}
		tables = append(tables, t)
	}
	return tables, rows.Err()
}

// ListColumns returns columns in a table (MySQL)
func (b *MySQLBrowser) ListColumns(ctx context.Context, database, table string) ([]ColumnInfo, error) {
	if !isValidIdentifier(database) || !isValidIdentifier(table) {
		return nil, fmt.Errorf("invalid database or table name")
	}

	rows, err := b.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT
			column_name,
			column_type,
			is_nullable = 'YES' AS nullable,
			column_default,
			column_comment
		FROM information_schema.columns
		WHERE table_schema = '%s' AND table_name = '%s'
		ORDER BY ordinal_position
	`, database, table))
	if err != nil {
		return nil, fmt.Errorf("list columns failed: %w", err)
	}
	defer rows.Close()

	var columns []ColumnInfo
	for rows.Next() {
		var c ColumnInfo
		var defaultVal, comment sql.NullString
		err := rows.Scan(&c.Name, &c.Type, &c.Nullable, &defaultVal, &comment)
		if err != nil {
			return nil, err
		}
		if defaultVal.Valid {
			c.Default = defaultVal.String
		}
		if comment.Valid {
			c.Comment = comment.String
		}
		columns = append(columns, c)
	}
	return columns, rows.Err()
}

// GetTableRows returns paginated rows from a table (MySQL)
func (b *MySQLBrowser) GetTableRows(ctx context.Context, database, table string, limit, offset int) ([]RowData, error) {
	if !isValidIdentifier(database) || !isValidIdentifier(table) {
		return nil, fmt.Errorf("invalid database or table name")
	}

	if limit > MaxBrowserRowLimit {
		limit = MaxBrowserRowLimit
	}
	if limit <= 0 {
		limit = DefaultBrowserRowLimit
	}

	// MySQL uses backticks for identifier escaping
	query := fmt.Sprintf("SELECT * FROM `%s`.`%s` LIMIT ? OFFSET ?", database, table)
	rows, err := b.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("query table rows failed: %w", err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var result []RowData
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range columns {
			valuePtrs[i] = &values[i]
		}

		err := rows.Scan(valuePtrs...)
		if err != nil {
			return nil, err
		}

		rowData := RowData{Values: make(map[string]interface{})}
		for i, col := range columns {
			rowData.Values[col] = values[i]
		}
		result = append(result, rowData)
	}

	return result, rows.Err()
}

// SearchTableData searches table data with a validated column/value filter.
func (b *MySQLBrowser) SearchTableData(ctx context.Context, database, table, column, query string, limit, offset int) ([]RowData, error) {
	if !isValidIdentifier(database) || !isValidIdentifier(table) || !isValidIdentifier(column) {
		return nil, fmt.Errorf("invalid database/table/column name")
	}
	if limit <= 0 {
		limit = DefaultBrowserRowLimit
	}
	if limit > MaxBrowserRowLimit {
		limit = MaxBrowserRowLimit
	}
	if offset < 0 {
		offset = 0
	}

	querySQL := fmt.Sprintf("SELECT * FROM `%s`.`%s` WHERE `%s` LIKE ? LIMIT ? OFFSET ?", database, table, column)
	rows, err := b.db.QueryContext(ctx, querySQL, "%"+query+"%", limit, offset)
	if err != nil {
		return nil, fmt.Errorf("search table data failed: %w", err)
	}
	defer rows.Close()

	var result []RowData
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range columns {
			valuePtrs[i] = &values[i]
		}
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}
		rowData := RowData{Values: make(map[string]interface{})}
		for i, col := range columns {
			rowData.Values[col] = values[i]
		}
		result = append(result, rowData)
	}
	return result, rows.Err()
}

// --- Helper functions ---

// isValidIdentifier checks if a name is a valid database/schema/table identifier
// Prevents SQL injection via identifier names (spec #23)
func isValidIdentifier(name string) bool {
	// Allow alphanumeric, underscore, hyphen
	// Must start with letter or underscore
	pattern := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$`)
	return pattern.MatchString(name)
}

// MongoDBBrowser implements read-only document browsing for MongoDB (stub)
type MongoDBBrowser struct {
	// Would require mongo-go-driver
}

// RedisKeyBrowser implements read-only key browsing for Redis
type RedisKeyBrowser struct {
	// Would require redis-go or similar
	// Use SCAN for safe key discovery (spec #88)
}

// ValkeyKeyBrowser implements read-only key browsing for Valkey (compatible with Redis)
type ValkeyKeyBrowser struct {
	// Same as RedisKeyBrowser using Valkey-compatible protocol
}
