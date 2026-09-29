package services

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrDatabaseLogsUnsupported means this engine has no SQL-reachable log
// source at all from a plain client connection (MongoDB/Redis/Valkey) --
// distinct from ErrDatabaseLogsNotConfigured, which means the engine
// *can* expose logs this way but this particular server isn't set up for
// it yet.
var ErrDatabaseLogsUnsupported = errors.New("log viewing is not supported for this database engine yet")

// ErrDatabaseLogsNotConfigured means the server-side logging setting or
// the monitoring credential's privileges block reading logs -- the
// wrapped message names the specific fix (e.g. "enable csvlog", "grant
// pg_read_server_files").
var ErrDatabaseLogsNotConfigured = errors.New("this database server is not configured to make its logs readable")

// CollectDirectDatabaseLogs fetches recent log entries directly from the
// database server itself -- same "one connect, backend-defined
// read-only calls only" discipline as CollectDirectDeepMetrics (never a
// client-supplied query). There is no universal "SELECT * FROM logs"
// across engines, so each one needs its own approach: Postgres logs to
// files (read via pg_read_file, gated on csvlog + privilege), MySQL/
// MariaDB can optionally log to queryable tables (mysql.general_log/
// slow_log, off by default), and MongoDB/Redis/Valkey have no
// SQL-reachable log source from a plain client connection at all.
func CollectDirectDatabaseLogs(ctx context.Context, conn DirectDatabaseConnection, from, to time.Time, limit int) ([]LogEntry, error) {
	switch conn.Type {
	case DBTypePostgreSQL:
		return collectPostgresLogsDirectly(ctx, conn, from, to, limit)
	case DBTypeMySQL, DBTypeMariaDB:
		return collectMySQLLogsDirectly(ctx, conn, from, to, limit)
	default:
		return nil, fmt.Errorf("%w: %s", ErrDatabaseLogsUnsupported, conn.Type)
	}
}

// --- PostgreSQL: read the active csvlog file via pg_read_file ---

func collectPostgresLogsDirectly(ctx context.Context, conn DirectDatabaseConnection, from, to time.Time, limit int) ([]LogEntry, error) {
	pgxConn, err := pgx.Connect(ctx, postgresConnString(conn))
	if err != nil {
		return nil, classifyPgError(err)
	}
	defer pgxConn.Close(ctx)

	// A permission-denied error here is common on managed Postgres
	// (DigitalOcean, RDS, Cloud SQL, ...): these providers routinely
	// revoke pg_current_logfile/pg_read_file from every role they hand
	// out, including their "admin" one, as a platform-level restriction
	// rather than a grantable privilege -- worth saying plainly rather
	// than pointing at a server setting the caller likely can't touch.
	var logFile *string
	if err := pgxConn.QueryRow(ctx, "SELECT pg_current_logfile('csvlog')").Scan(&logFile); err != nil {
		return nil, fmt.Errorf(
			"%w: the monitoring credential isn't allowed to read this server's logs (permission denied on pg_current_logfile) -- "+
				"many managed Postgres providers (DigitalOcean, RDS, Cloud SQL, ...) block this at the platform level for every role, "+
				"including their own admin account, so this may not be something you can grant -- %v",
			ErrDatabaseLogsNotConfigured, err,
		)
	}
	if logFile == nil || *logFile == "" {
		return nil, fmt.Errorf("%w: enable CSV logging on this server (add 'csvlog' to log_destination and set logging_collector = on) to view logs here", ErrDatabaseLogsNotConfigured)
	}

	var content string
	if err := pgxConn.QueryRow(ctx, "SELECT pg_read_file($1)", *logFile).Scan(&content); err != nil {
		return nil, fmt.Errorf("%w: reading server logs needs the pg_read_server_files role (or superuser) granted to the monitoring credential -- %v", ErrDatabaseLogsNotConfigured, err)
	}

	return parsePostgresCSVLog(content, from, to, limit), nil
}

// parsePostgresCSVLog reads only the first 14 columns of Postgres's CSV
// log format (log_time, user_name, database_name, process_id,
// connection_from, session_id, session_line_num, command_tag,
// session_start_time, virtual_transaction_id, transaction_id,
// error_severity, sql_state_code, message) -- that prefix has been
// stable since Postgres 8.3, so this stays correct even on servers that
// later append more trailing columns (17+ added leader_pid/query_id
// etc). Only reads the *current* (active) log file, not older rotated
// ones -- a reasonable, clearly-scoped limit given the default daily
// rotation.
func parsePostgresCSVLog(content string, from, to time.Time, limit int) []LogEntry {
	reader := csv.NewReader(strings.NewReader(content))
	reader.FieldsPerRecord = -1

	var entries []LogEntry
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A multi-line message can momentarily desync a naive
			// reader -- skip the bad record rather than failing the
			// whole fetch over one malformed line.
			continue
		}
		if len(record) < 14 {
			continue
		}
		ts, ok := parsePostgresLogTimestamp(record[0])
		if !ok {
			continue
		}
		if !from.IsZero() && ts.Before(from) {
			continue
		}
		if !to.IsZero() && ts.After(to) {
			continue
		}
		entries = append(entries, LogEntry{
			Timestamp: ts.Format(time.RFC3339Nano),
			Severity:  record[11],
			Source:    record[2],
			Message:   record[13],
		})
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Timestamp > entries[j].Timestamp })
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	return entries
}

func parsePostgresLogTimestamp(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02 15:04:05.000 MST", "2006-01-02 15:04:05 MST"} {
		if ts, err := time.Parse(layout, s); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}

// --- MySQL/MariaDB: read mysql.general_log/mysql.slow_log, if enabled ---

func collectMySQLLogsDirectly(ctx context.Context, conn DirectDatabaseConnection, from, to time.Time, limit int) ([]LogEntry, error) {
	db, err := mysqlOpen(conn)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var varName, logOutput string
	if err := db.QueryRowContext(ctx, "SHOW VARIABLES LIKE 'log_output'").Scan(&varName, &logOutput); err != nil {
		return nil, classifyMySQLError(err)
	}
	if !strings.Contains(strings.ToUpper(logOutput), "TABLE") {
		return nil, fmt.Errorf("%w: enable table-based logging on this server (SET GLOBAL log_output='TABLE', then general_log=ON and/or slow_query_log=ON) to view logs here", ErrDatabaseLogsNotConfigured)
	}

	// A zero from/to (no range requested) must mean "unbounded", not
	// literally BETWEEN '0001-01-01' AND '0001-01-01' -- which would
	// match nothing at all, silently turning "show me recent logs" into
	// an empty result every time.
	rangeFrom, rangeTo := from, to
	if rangeFrom.IsZero() {
		rangeFrom = time.Unix(0, 0)
	}
	if rangeTo.IsZero() {
		rangeTo = time.Now()
	}

	general, generalErr := queryMySQLLogTable(ctx, db,
		"SELECT event_time, user_host, argument FROM mysql.general_log WHERE event_time BETWEEN ? AND ? ORDER BY event_time DESC LIMIT ?",
		rangeFrom, rangeTo, limit, "INFO")
	slow, slowErr := queryMySQLLogTable(ctx, db,
		"SELECT start_time, user_host, sql_text FROM mysql.slow_log WHERE start_time BETWEEN ? AND ? ORDER BY start_time DESC LIMIT ?",
		rangeFrom, rangeTo, limit, "WARNING")
	if generalErr != nil && slowErr != nil {
		return nil, fmt.Errorf("%w: the monitoring credential can't read mysql.general_log/mysql.slow_log -- grant it SELECT on the mysql database", ErrDatabaseLogsNotConfigured)
	}

	entries := append(general, slow...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Timestamp > entries[j].Timestamp })
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	return entries, nil
}

func queryMySQLLogTable(ctx context.Context, db *sql.DB, query string, from, to time.Time, limit int, severity string) ([]LogEntry, error) {
	rows, err := db.QueryContext(ctx, query, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []LogEntry
	for rows.Next() {
		// Scanned as a string, not time.Time: the shared connection DSN
		// (mysqlDSN, direct_database_adapter.go) doesn't set
		// ParseTime=true -- other collectors sharing that DSN read
		// numeric/VARCHAR performance_schema columns, never a DATETIME,
		// so changing it there would be a wider blast radius than this
		// one query needs. Parsed here instead.
		var eventTimeStr, userHost, text string
		if err := rows.Scan(&eventTimeStr, &userHost, &text); err != nil {
			continue
		}
		eventTime, ok := parseMySQLDatetime(eventTimeStr)
		if !ok {
			continue
		}
		entries = append(entries, LogEntry{
			Timestamp: eventTime.Format(time.RFC3339Nano), Severity: severity, Source: userHost, Message: text,
		})
	}
	return entries, rows.Err()
}

func parseMySQLDatetime(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02 15:04:05.000000", "2006-01-02 15:04:05"} {
		if ts, err := time.Parse(layout, s); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}
