package services

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
)

// DatabaseOperationType is the closed set of backend-defined remediation
// templates (spec: "Never allow arbitrary SQL/Redis/MongoDB/shell
// commands... All commands/operations must be backend-defined templates").
// A frontend can only ever request one of these named types with a small,
// backend-validated parameter set -- there is no code path anywhere in
// this package that turns client input directly into a query/command
// string.
type DatabaseOperationType string

const (
	DBOpTypeRestart           DatabaseOperationType = "RESTART"
	DBOpTypeCancelQuery       DatabaseOperationType = "CANCEL_QUERY"
	DBOpTypeTerminateSession  DatabaseOperationType = "TERMINATE_SESSION"
	DBOpTypeVacuum            DatabaseOperationType = "VACUUM"
	DBOpTypeAnalyze           DatabaseOperationType = "ANALYZE"
	DBOpTypeRedisMaintenance  DatabaseOperationType = "REDIS_MAINTENANCE"
	DBOpTypeReplicationAction DatabaseOperationType = "REPLICATION_ACTION"
	DBOpTypeConfigChange      DatabaseOperationType = "CONFIG_CHANGE"
	DBOpTypeUpgrade           DatabaseOperationType = "UPGRADE"
)

var ErrDatabaseOperationUnsupported = errors.New("this operation is not supported for this database")
var ErrDatabaseOperationInvalidParams = errors.New("invalid operation parameters")

// OperationCapability is one operation an adapter declares it actually
// supports for a given engine -- spec: "Do not implement every operation
// blindly. Each database adapter must declare its supported operations"
// and "Do not force unsupported operations onto adapters."
type OperationCapability struct {
	Type              DatabaseOperationType
	Label             string
	Destructive       bool   // shown with stronger confirmation framing
	Reversible        string // "N/A" | "Available" | "Not Available" -- never claimed unless genuinely true
	RequiresTargetID  bool   // a specific session/query/connection id (spec's Lock/Query remediation)
	ImpactDescription string
}

// GetOperationCapabilities returns exactly what this engine can safely
// do through this project's direct-TCP/TLS-only architecture -- no SSH,
// no shell, so RESTART/REPLICATION_ACTION/CONFIG_CHANGE/UPGRADE are never
// declared supported by any engine here (spec: "Admin must explicitly
// initiate any future supported replication operation" / "Do not
// automatically upgrade" -- read together with "no shell access" this
// means: not yet implementable at all, not merely gated).
func GetOperationCapabilities(dbType DatabaseType) []OperationCapability {
	switch dbType {
	case DBTypePostgreSQL:
		return []OperationCapability{
			{Type: DBOpTypeCancelQuery, Label: "Cancel Query", Destructive: false, Reversible: "N/A", RequiresTargetID: true,
				ImpactDescription: "May terminate the currently executing query on this session. The connection itself stays open."},
			{Type: DBOpTypeTerminateSession, Label: "Terminate Session", Destructive: true, Reversible: "N/A", RequiresTargetID: true,
				ImpactDescription: "Forcibly closes this database connection. Any in-progress query is rolled back and the client must reconnect."},
			{Type: DBOpTypeVacuum, Label: "VACUUM", Destructive: false, Reversible: "N/A", RequiresTargetID: false,
				ImpactDescription: "Reclaims dead-tuple storage across the connected database. Runs in the background; may briefly increase disk I/O."},
			{Type: DBOpTypeAnalyze, Label: "ANALYZE", Destructive: false, Reversible: "N/A", RequiresTargetID: false,
				ImpactDescription: "Refreshes query-planner statistics across the connected database. May briefly increase read load."},
		}
	case DBTypeMySQL, DBTypeMariaDB:
		return []OperationCapability{
			{Type: DBOpTypeCancelQuery, Label: "Cancel Query", Destructive: false, Reversible: "N/A", RequiresTargetID: true,
				ImpactDescription: "Stops the currently executing statement on this connection. The connection itself stays open."},
			{Type: DBOpTypeTerminateSession, Label: "Terminate Session", Destructive: true, Reversible: "N/A", RequiresTargetID: true,
				ImpactDescription: "Forcibly closes this database connection. Any in-progress transaction is rolled back and the client must reconnect."},
		}
	case DBTypeMongoDB:
		return []OperationCapability{
			{Type: DBOpTypeTerminateSession, Label: "Kill Operation", Destructive: true, Reversible: "N/A", RequiresTargetID: true,
				ImpactDescription: "Forcibly stops the currently running operation. Any in-progress write may be left partially applied per MongoDB's own kill-op semantics."},
		}
	case DBTypeRedis, DBTypeValkey:
		return []OperationCapability{
			{Type: DBOpTypeTerminateSession, Label: "Kill Client Connection", Destructive: true, Reversible: "N/A", RequiresTargetID: true,
				ImpactDescription: "Forcibly closes this client's connection. The client must reconnect."},
			{Type: DBOpTypeRedisMaintenance, Label: "Background Save (BGSAVE)", Destructive: false, Reversible: "N/A", RequiresTargetID: false,
				ImpactDescription: "Triggers a non-blocking background save of the dataset to disk. Brief CPU and disk I/O increase while it runs."},
		}
	default:
		return nil
	}
}

func findCapability(dbType DatabaseType, opType DatabaseOperationType) (OperationCapability, bool) {
	for _, c := range GetOperationCapabilities(dbType) {
		if c.Type == opType {
			return c, true
		}
	}
	return OperationCapability{}, false
}

// ValidateOperationParams verifies opType is genuinely supported for
// dbType and that every parameter this specific operation needs is
// present and well-formed -- point 7/8 of Step 14's ten-point validation
// checklist ("Operation is supported" / "Parameters are valid").
func ValidateOperationParams(dbType DatabaseType, opType DatabaseOperationType, params map[string]string) error {
	cap_, ok := findCapability(dbType, opType)
	if !ok {
		return fmt.Errorf("%w: %s is not supported for %s", ErrDatabaseOperationUnsupported, opType, dbType)
	}
	if !cap_.RequiresTargetID {
		return nil
	}
	targetID := strings.TrimSpace(params["target_id"])
	if targetID == "" {
		return fmt.Errorf("%w: target_id is required for %s", ErrDatabaseOperationInvalidParams, opType)
	}
	switch dbType {
	case DBTypePostgreSQL, DBTypeMySQL, DBTypeMariaDB, DBTypeRedis, DBTypeValkey:
		if _, err := strconv.ParseUint(targetID, 10, 64); err != nil {
			return fmt.Errorf("%w: target_id must be numeric for %s", ErrDatabaseOperationInvalidParams, dbType)
		}
	case DBTypeMongoDB:
		// MongoDB opids are either a plain integer or "shardName:opid" on a
		// sharded cluster -- both are opaque identifiers taken verbatim
		// from db.currentOp()'s own output, never client-composed.
	}
	return nil
}

// PreviewOperation renders exactly what the backend intends to run --
// spec: "Before execution, Admin should see exactly what the system
// intends to execute... Do not expose credentials." Pure and read-only;
// never opens a connection.
func PreviewOperation(dbType DatabaseType, opType DatabaseOperationType, params map[string]string) (commandPreview, impact string, err error) {
	cap_, ok := findCapability(dbType, opType)
	if !ok {
		return "", "", fmt.Errorf("%w: %s is not supported for %s", ErrDatabaseOperationUnsupported, opType, dbType)
	}
	if err := ValidateOperationParams(dbType, opType, params); err != nil {
		return "", "", err
	}
	targetID := params["target_id"]

	switch dbType {
	case DBTypePostgreSQL:
		switch opType {
		case DBOpTypeCancelQuery:
			commandPreview = fmt.Sprintf("SELECT pg_cancel_backend(%s);", targetID)
		case DBOpTypeTerminateSession:
			commandPreview = fmt.Sprintf("SELECT pg_terminate_backend(%s);", targetID)
		case DBOpTypeVacuum:
			commandPreview = "VACUUM;"
		case DBOpTypeAnalyze:
			commandPreview = "ANALYZE;"
		}
	case DBTypeMySQL, DBTypeMariaDB:
		switch opType {
		case DBOpTypeCancelQuery:
			commandPreview = fmt.Sprintf("KILL QUERY %s;", targetID)
		case DBOpTypeTerminateSession:
			commandPreview = fmt.Sprintf("KILL %s;", targetID)
		}
	case DBTypeMongoDB:
		commandPreview = fmt.Sprintf(`db.adminCommand({killOp: 1, op: %s})`, targetID)
	case DBTypeRedis, DBTypeValkey:
		switch opType {
		case DBOpTypeTerminateSession:
			commandPreview = fmt.Sprintf("CLIENT KILL ID %s", targetID)
		case DBOpTypeRedisMaintenance:
			commandPreview = "BGSAVE"
		}
	}
	return commandPreview, cap_.ImpactDescription, nil
}

// ExecuteOperation runs the one backend-defined command this operation
// type maps to, over a fresh direct connection -- never a client-supplied
// query/command of any kind (every string sent to the target database
// here is either a fixed literal or a value ValidateOperationParams has
// already confirmed is a bare, engine-appropriate identifier).
func ExecuteOperation(ctx context.Context, conn DirectDatabaseConnection, opType DatabaseOperationType, params map[string]string) (resultSummary string, detail map[string]any, err error) {
	if err := ValidateOperationParams(conn.Type, opType, params); err != nil {
		return "", nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, conn.QueryTimeout)
	defer cancel()

	switch conn.Type {
	case DBTypePostgreSQL:
		return executePostgresOperation(ctx, conn, opType, params)
	case DBTypeMySQL, DBTypeMariaDB:
		return executeMySQLOperation(ctx, conn, opType, params)
	case DBTypeMongoDB:
		return executeMongoOperation(ctx, conn, opType, params)
	case DBTypeRedis, DBTypeValkey:
		return executeRedisOperation(ctx, conn, opType, params)
	default:
		return "", nil, fmt.Errorf("%w: %s", ErrDatabaseUnsupported, conn.Type)
	}
}

func executePostgresOperation(ctx context.Context, conn DirectDatabaseConnection, opType DatabaseOperationType, params map[string]string) (string, map[string]any, error) {
	pgxConn, err := pgx.Connect(ctx, postgresConnString(conn))
	if err != nil {
		return "", nil, classifyPgError(err)
	}
	defer pgxConn.Close(ctx)

	switch opType {
	case DBOpTypeCancelQuery, DBOpTypeTerminateSession:
		pid, _ := strconv.ParseInt(params["target_id"], 10, 32)
		fn := "pg_cancel_backend"
		if opType == DBOpTypeTerminateSession {
			fn = "pg_terminate_backend"
		}
		var ok bool
		if err := pgxConn.QueryRow(ctx, fmt.Sprintf("SELECT %s($1)", fn), int32(pid)).Scan(&ok); err != nil {
			return "", nil, fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
		}
		if !ok {
			return "", map[string]any{"pid": pid, "signaled": false}, fmt.Errorf("no active session found with pid %d", pid)
		}
		return fmt.Sprintf("Signal sent to backend %d.", pid), map[string]any{"pid": pid, "signaled": true}, nil
	case DBOpTypeVacuum:
		if _, err := pgxConn.Exec(ctx, "VACUUM"); err != nil {
			return "", nil, fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
		}
		return "VACUUM completed.", nil, nil
	case DBOpTypeAnalyze:
		if _, err := pgxConn.Exec(ctx, "ANALYZE"); err != nil {
			return "", nil, fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
		}
		return "ANALYZE completed.", nil, nil
	default:
		return "", nil, fmt.Errorf("%w: %s", ErrDatabaseOperationUnsupported, opType)
	}
}

func executeMySQLOperation(ctx context.Context, conn DirectDatabaseConnection, opType DatabaseOperationType, params map[string]string) (string, map[string]any, error) {
	db, err := mysqlOpen(conn)
	if err != nil {
		return "", nil, err
	}
	defer db.Close()

	id, _ := strconv.ParseUint(params["target_id"], 10, 64)
	stmt := fmt.Sprintf("KILL %d", id)
	if opType == DBOpTypeCancelQuery {
		stmt = fmt.Sprintf("KILL QUERY %d", id)
	}
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		return "", nil, classifyMySQLError(err)
	}
	verb := "Connection"
	if opType == DBOpTypeCancelQuery {
		verb = "Query"
	}
	return fmt.Sprintf("%s %d terminated.", verb, id), map[string]any{"id": id}, nil
}

func executeMongoOperation(ctx context.Context, conn DirectDatabaseConnection, opType DatabaseOperationType, params map[string]string) (string, map[string]any, error) {
	client, err := mongoConnect(ctx, conn)
	if err != nil {
		return "", nil, err
	}
	defer client.Disconnect(ctx)

	opID := params["target_id"]
	var opValue any = opID
	if n, err := strconv.ParseInt(opID, 10, 64); err == nil {
		opValue = n
	}
	admin := client.Database("admin")
	if err := admin.RunCommand(ctx, bson.D{{Key: "killOp", Value: 1}, {Key: "op", Value: opValue}}).Err(); err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
	}
	return fmt.Sprintf("Kill signal sent for operation %s.", opID), map[string]any{"op_id": opID}, nil
}

func executeRedisOperation(ctx context.Context, conn DirectDatabaseConnection, opType DatabaseOperationType, params map[string]string) (string, map[string]any, error) {
	client := redis.NewClient(redisOptions(conn))
	defer client.Close()

	switch opType {
	case DBOpTypeTerminateSession:
		id := params["target_id"]
		if err := client.Do(ctx, "CLIENT", "KILL", "ID", id).Err(); err != nil {
			return "", nil, classifyRedisError(err)
		}
		return fmt.Sprintf("Client %s killed.", id), map[string]any{"client_id": id}, nil
	case DBOpTypeRedisMaintenance:
		if err := client.Do(ctx, "BGSAVE").Err(); err != nil {
			return "", nil, classifyRedisError(err)
		}
		return "Background save started.", nil, nil
	default:
		return "", nil, fmt.Errorf("%w: %s", ErrDatabaseOperationUnsupported, opType)
	}
}
