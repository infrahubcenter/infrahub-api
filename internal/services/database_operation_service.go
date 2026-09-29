package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

var (
	ErrDBOpDatabaseNotFound       = errors.New("database not found")
	ErrDBOpNotFound               = errors.New("database operation not found")
	ErrDBOpAlreadyActive          = errors.New("another operation is already active for this database")
	ErrDBOpCancelUnavailable      = errors.New("cancellation is unavailable once the operation has started running")
	ErrDBOpNotWaitingConfirmation = errors.New("this operation is not waiting for confirmation")
	ErrDBOpNotFailed              = errors.New("only a failed operation can be retried")
	ErrDBOpNotTerminal            = errors.New("only a completed operation (success, failed, cancelled, or timed out) can be deleted")
)

// DatabaseOperationService is the Step 14 orchestrator: Admin previews ->
// requests a plan (WAITING_CONFIRMATION) -> confirms (transactional claim,
// mirroring RebootExecutionService.RequestReboot's exclusivity check) ->
// async worker runs Run() -> full pre-flight re-check -> connect -> execute
// exactly one backend-defined command via database_operation_adapter.go ->
// post-operation health verification -> terminal status. Reuses
// StandaloneDatabaseCredentialService/DirectDatabaseConnection/
// TestDirectConnection/CollectDirectDatabaseMetrics (Step 13) wholesale
// for everything that isn't unique to operations themselves.
type DatabaseOperationService struct {
	store            *repository.Store
	credentials      *StandaloneDatabaseCredentialService
	audit            *AuditService
	connectTimeout   time.Duration
	commandTimeout   time.Duration
	operationTimeout time.Duration
	healthThresholds DatabaseHealthThresholds
	logMaxBytes      int64
}

// NewDatabaseOperationService creates a DatabaseOperationService.
func NewDatabaseOperationService(
	store *repository.Store, credentials *StandaloneDatabaseCredentialService, audit *AuditService,
	connectTimeout, commandTimeout, operationTimeout time.Duration, healthThresholds DatabaseHealthThresholds, logMaxBytes int64,
) *DatabaseOperationService {
	return &DatabaseOperationService{
		store: store, credentials: credentials, audit: audit,
		connectTimeout: connectTimeout, commandTimeout: commandTimeout, operationTimeout: operationTimeout,
		healthThresholds: healthThresholds, logMaxBytes: logMaxBytes,
	}
}

// Preview computes exactly what the backend would run for opType/params
// against databaseID -- spec's dedicated dry-run endpoint. Never opens a
// connection, never creates a database_operations row.
func (s *DatabaseOperationService) Preview(ctx context.Context, databaseID uuid.UUID, opType DatabaseOperationType, params map[string]string) (commandPreview, impact string, err error) {
	db, err := s.store.GetDatabaseByID(ctx, databaseID)
	if err != nil || db.DeletedAt.Valid {
		return "", "", ErrDBOpDatabaseNotFound
	}
	return PreviewOperation(DatabaseType(db.Type), opType, params)
}

// RunPrecheck is Step 14's ten-point validation checklist, points 4-9
// (existence/authorization are checked by the handler before this is ever
// called, points 1-3/10 -- mirrors RebootExecutionService.RunPrecheck's
// exact split of responsibilities). Never executes anything.
func (s *DatabaseOperationService) RunPrecheck(ctx context.Context, databaseID uuid.UUID, opType DatabaseOperationType, params map[string]string, excludeOperationID uuid.UUID) (PrecheckReport, error) {
	report := PrecheckReport{AllPassed: true}

	db, err := s.store.GetDatabaseByID(ctx, databaseID)
	if err != nil || db.DeletedAt.Valid {
		report.add("database_exists", PrecheckFail, "Database not found.")
		return report, nil
	}
	report.add("database_exists", PrecheckPass, "Database exists.")

	if _, ok := findCapability(DatabaseType(db.Type), opType); !ok {
		report.add("operation_supported", PrecheckFail, fmt.Sprintf("%s is not a supported operation for %s databases.", opType, db.Type))
	} else {
		report.add("operation_supported", PrecheckPass, "Operation is supported for this database engine.")
	}

	if err := ValidateOperationParams(DatabaseType(db.Type), opType, params); err != nil {
		report.add("parameters_valid", PrecheckFail, err.Error())
	} else {
		report.add("parameters_valid", PrecheckPass, "Parameters are valid.")
	}

	username, password, credErr := s.credentials.GetCredential(ctx, databaseID)
	if credErr != nil {
		report.add("database_reachable", PrecheckFail, "No monitoring credential is configured for this database.")
	} else {
		conn := s.buildConnection(db, username, password)
		if testErr := TestDirectConnection(ctx, conn); testErr != nil {
			report.add("database_reachable", PrecheckFail, "Database is not reachable: "+testErr.Error())
		} else {
			report.add("database_reachable", PrecheckPass, "Database is reachable.")
		}
	}

	var excludeParam pgtype.UUID
	if excludeOperationID != uuid.Nil {
		excludeParam = pgutil.NullUUID(&excludeOperationID)
	}
	if _, err := s.store.GetActiveDatabaseOperationForDatabaseLocked(ctx, generated.GetActiveDatabaseOperationForDatabaseLockedParams{
		DatabaseID: databaseID, ExcludeOperationID: excludeParam,
	}); err == nil {
		report.add("no_conflicting_operation", PrecheckFail, "Another operation is already active for this database.")
	} else if errors.Is(err, pgx.ErrNoRows) {
		report.add("no_conflicting_operation", PrecheckPass, "No conflicting operation is active.")
	} else {
		report.add("no_conflicting_operation", PrecheckUnknown, "Could not determine whether a conflicting operation is active.")
	}

	return report, nil
}

func (s *DatabaseOperationService) buildConnection(db generated.Database, username, password string) DirectDatabaseConnection {
	return DirectDatabaseConnection{
		Type: DatabaseType(db.Type), Host: db.Host, Port: int(db.Port), Username: username, Password: password,
		Database: pgutil.TextOrEmpty(db.DatabaseName), TLSEnabled: db.TlsEnabled, TLSSkipVerify: db.TlsSkipVerify,
		ConnectTimeout: s.connectTimeout, QueryTimeout: s.commandTimeout,
	}
}

// RequestOperation creates the operation plan (spec's "Operation Plan"
// step): validates the database exists and the operation/parameters are
// genuinely supported, computes the command preview, and persists a
// WAITING_CONFIRMATION row -- never executes anything, never even tests
// connectivity (that happens at Confirm/Run time, closer to actual
// execution, so a plan reviewed five minutes ago doesn't go stale).
func (s *DatabaseOperationService) RequestOperation(
	ctx context.Context, databaseID uuid.UUID, opType DatabaseOperationType, params map[string]string,
	reason string, recommendationID *uuid.UUID, actorID uuid.UUID,
) (generated.DatabaseOperation, error) {
	db, err := s.store.GetDatabaseByID(ctx, databaseID)
	if err != nil || db.DeletedAt.Valid {
		return generated.DatabaseOperation{}, ErrDBOpDatabaseNotFound
	}
	if err := ValidateOperationParams(DatabaseType(db.Type), opType, params); err != nil {
		return generated.DatabaseOperation{}, err
	}
	commandPreview, _, err := PreviewOperation(DatabaseType(db.Type), opType, params)
	if err != nil {
		return generated.DatabaseOperation{}, err
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return generated.DatabaseOperation{}, fmt.Errorf("encode parameters: %w", err)
	}

	op, err := s.store.CreateDatabaseOperation(ctx, generated.CreateDatabaseOperationParams{
		DatabaseID: databaseID, OperationType: string(opType), RequestedBy: pgutil.NullUUID(&actorID),
		Reason: pgutil.Text(reason), Parameters: paramsJSON, CommandPreview: commandPreview,
		RecommendationID: pgutil.NullUUID(recommendationID),
	})
	if err != nil {
		return generated.DatabaseOperation{}, fmt.Errorf("create database operation: %w", err)
	}

	_ = s.audit.Log(ctx, AuditEvent{
		UserID: &actorID, Action: AuditDatabaseOperationRequested, ResourceType: "DATABASE", ResourceID: &db.ResourceID,
		Metadata: map[string]any{"database_operation_id": op.ID, "operation_type": string(opType)},
	})
	return op, nil
}

// Confirm is the explicit admin confirmation step (spec's Confirmation ->
// Execute transition): atomically claims database-level exclusivity
// (mirrors RequestReboot's transactional claim exactly -- "Prevent two
// conflicting operations from running simultaneously against the same
// database") and moves the plan from WAITING_CONFIRMATION to PENDING,
// ready for a worker to pick up. Returns the confirmed row; the caller
// (handler) is responsible for enqueueing it to the worker pool.
func (s *DatabaseOperationService) Confirm(ctx context.Context, operationID, actorID uuid.UUID) (generated.DatabaseOperation, error) {
	current, err := s.store.GetDatabaseOperationByID(ctx, operationID)
	if err != nil {
		return generated.DatabaseOperation{}, ErrDBOpNotFound
	}
	if DatabaseOperationStatus(current.Status) != DBOpWaitingConfirmation {
		return generated.DatabaseOperation{}, ErrDBOpNotWaitingConfirmation
	}

	var confirmed generated.DatabaseOperation
	err = s.store.WithTx(ctx, func(q *generated.Queries) error {
		if _, lockErr := q.GetActiveDatabaseOperationForDatabaseLocked(ctx, generated.GetActiveDatabaseOperationForDatabaseLockedParams{
			DatabaseID: current.DatabaseID, ExcludeOperationID: pgutil.NullUUID(&operationID),
		}); lockErr == nil {
			return ErrDBOpAlreadyActive
		} else if !errors.Is(lockErr, pgx.ErrNoRows) {
			return fmt.Errorf("check active operation: %w", lockErr)
		}

		updated, confirmErr := q.ConfirmDatabaseOperation(ctx, operationID)
		if confirmErr != nil {
			return fmt.Errorf("confirm database operation: %w", confirmErr)
		}
		confirmed = updated
		return nil
	})
	if err != nil {
		return generated.DatabaseOperation{}, err
	}

	db, _ := s.store.GetDatabaseByID(ctx, current.DatabaseID)
	_ = s.audit.Log(ctx, AuditEvent{
		UserID: &actorID, Action: AuditDatabaseOperationConfirmed, ResourceType: "DATABASE", ResourceID: &db.ResourceID,
		Metadata: map[string]any{"database_operation_id": operationID, "operation_type": current.OperationType},
	})
	return confirmed, nil
}

// Cancel is only permitted before execution has actually started (spec's
// Lock/Query remediation: "Never automatically kill sessions" -- once
// RUNNING, the backend-defined command may already be in flight and there
// is no safe way to abort it mid-execution, mirroring RebootExecutionService.Cancel).
func (s *DatabaseOperationService) Cancel(ctx context.Context, operationID, actorID uuid.UUID) (generated.DatabaseOperation, error) {
	op, err := s.store.GetDatabaseOperationByID(ctx, operationID)
	if err != nil {
		return generated.DatabaseOperation{}, ErrDBOpNotFound
	}
	status := DatabaseOperationStatus(op.Status)
	if status != DBOpWaitingConfirmation && status != DBOpPending {
		return op, ErrDBOpCancelUnavailable
	}
	if err := ValidateDatabaseOperationTransition(status, DBOpCancelled); err != nil {
		return op, err
	}
	updated, err := s.store.UpdateDatabaseOperationStatus(ctx, generated.UpdateDatabaseOperationStatusParams{
		ID: operationID, Status: string(DBOpCancelled), ErrorSummary: pgutil.Text("Cancelled by admin before execution started."),
	})
	if err != nil {
		return op, fmt.Errorf("cancel database operation: %w", err)
	}
	db, _ := s.store.GetDatabaseByID(ctx, op.DatabaseID)
	_ = s.audit.Log(ctx, AuditEvent{
		UserID: &actorID, Action: AuditDatabaseOperationCancelled, ResourceType: "DATABASE", ResourceID: &db.ResourceID,
		Metadata: map[string]any{"database_operation_id": operationID},
	})
	return updated, nil
}

// Delete permanently removes one operation's history row -- only once it
// can no longer be claimed or executed by the worker (mirrors Cancel's own
// status gate, but the other direction: terminal-only instead of
// pre-execution-only). Never resurrects anything; to run the same thing
// again an admin still goes through Retry/RequestOperation from scratch.
func (s *DatabaseOperationService) Delete(ctx context.Context, operationID, actorID uuid.UUID) error {
	op, err := s.store.GetDatabaseOperationByID(ctx, operationID)
	if err != nil {
		return ErrDBOpNotFound
	}
	if !IsTerminalDatabaseOperationStatus(DatabaseOperationStatus(op.Status)) {
		return ErrDBOpNotTerminal
	}
	rows, err := s.store.DeleteDatabaseOperation(ctx, generated.DeleteDatabaseOperationParams{ID: operationID, DatabaseID: op.DatabaseID})
	if err != nil {
		return fmt.Errorf("delete database operation: %w", err)
	}
	if rows == 0 {
		return ErrDBOpNotFound
	}
	db, _ := s.store.GetDatabaseByID(ctx, op.DatabaseID)
	_ = s.audit.Log(ctx, AuditEvent{
		UserID: &actorID, Action: AuditDatabaseOperationDeleted, ResourceType: "DATABASE", ResourceID: &db.ResourceID,
		Metadata: map[string]any{"database_operation_id": operationID, "operation_type": op.OperationType},
	})
	return nil
}

// Retry creates a brand new WAITING_CONFIRMATION plan from a FAILED
// operation's exact type/parameters/target -- never resurrects or
// re-executes the original row, and still requires a fresh, explicit
// Confirm before anything runs (spec: "Admin may retry failed operations
// only after reviewing the failure. Do not automatically retry
// destructive operations.").
func (s *DatabaseOperationService) Retry(ctx context.Context, operationID, actorID uuid.UUID) (generated.DatabaseOperation, error) {
	original, err := s.store.GetDatabaseOperationByID(ctx, operationID)
	if err != nil {
		return generated.DatabaseOperation{}, ErrDBOpNotFound
	}
	if DatabaseOperationStatus(original.Status) != DBOpFailed {
		return generated.DatabaseOperation{}, ErrDBOpNotFailed
	}

	var params map[string]string
	_ = json.Unmarshal(original.Parameters, &params)
	reason := pgutil.TextOrEmpty(original.Reason)
	retryReason := fmt.Sprintf("Retry of operation %s.", original.ID)
	if reason != "" {
		retryReason = fmt.Sprintf("Retry of operation %s: %s", original.ID, reason)
	}
	var recommendationID *uuid.UUID
	if original.RecommendationID.Valid {
		id := pgutil.UUID(original.RecommendationID)
		recommendationID = &id
	}
	return s.RequestOperation(ctx, original.DatabaseID, DatabaseOperationType(original.OperationType), params, retryReason, recommendationID, actorID)
}

// RecoverInterruptedDatabaseOperations marks any operation left in a
// non-terminal state by an unclean prior shutdown as FAILED -- called once
// at startup, before the worker pool starts. Never automatically resumes
// or re-executes a command (mirrors RebootExecutionService's identical
// "no automatic retry, ever" startup sweep) -- a WAITING_CONFIRMATION or
// PENDING operation never actually reached the target database, so
// FAILED is unambiguous; a RUNNING one may or may not have completed its
// single command, which is exactly why Step 14 never auto-retries and
// requires the admin to review before requesting a new attempt.
func (s *DatabaseOperationService) RecoverInterruptedDatabaseOperations(ctx context.Context) (int, error) {
	ops, err := s.store.ListNonTerminalDatabaseOperations(ctx)
	if err != nil {
		return 0, fmt.Errorf("list non-terminal database operations: %w", err)
	}
	for _, op := range ops {
		msg := "Backend stopped while this operation was waiting for confirmation or queued; it was never sent to the database."
		if DatabaseOperationStatus(op.Status) == DBOpRunning {
			msg = "Backend stopped while this operation was running. Its outcome could not be confirmed -- verify the database's state manually before retrying."
		}
		_, _ = s.store.UpdateDatabaseOperationStatus(ctx, generated.UpdateDatabaseOperationStatusParams{
			ID: op.ID, Status: string(DBOpFailed), ErrorSummary: pgutil.Text(msg),
		})
	}
	return len(ops), nil
}
