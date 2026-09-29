package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// databaseOperationLogSink mirrors rebootLogSink exactly, against
// database_operation_logs instead of reboot_operation_logs -- never
// carries credentials or raw query/command text (spec: "Do not stream
// credentials or sensitive SQL/query text").
type databaseOperationLogSink struct {
	ctx         context.Context
	store       *repository.Store
	operationID uuid.UUID
	seq         int32
	maxBytes    int64
	written     int64
	truncated   bool
}

func newDatabaseOperationLogSink(ctx context.Context, store *repository.Store, operationID uuid.UUID, maxBytes int64) *databaseOperationLogSink {
	return &databaseOperationLogSink{ctx: ctx, store: store, operationID: operationID, maxBytes: maxBytes}
}

func (l *databaseOperationLogSink) system(message string) {
	if l.maxBytes > 0 && l.written >= l.maxBytes {
		if !l.truncated {
			l.truncated = true
			l.seq++
			_, _ = l.store.AppendDatabaseOperationLog(l.ctx, generated.AppendDatabaseOperationLogParams{
				DatabaseOperationID: l.operationID, SequenceNumber: l.seq, Stream: "SYSTEM",
				Message: "Output truncated: this operation's log exceeded DATABASE_OPERATION_LOG_MAX_BYTES.",
			})
		}
		return
	}
	l.seq++
	l.written += int64(len(message))
	_, _ = l.store.AppendDatabaseOperationLog(l.ctx, generated.AppendDatabaseOperationLogParams{
		DatabaseOperationID: l.operationID, SequenceNumber: l.seq, Stream: "SYSTEM", Message: message,
	})
}

func (s *DatabaseOperationService) transition(ctx context.Context, op generated.DatabaseOperation, to DatabaseOperationStatus, errSummary string) (generated.DatabaseOperation, error) {
	if err := ValidateDatabaseOperationTransition(DatabaseOperationStatus(op.Status), to); err != nil {
		return op, err
	}
	updated, err := s.store.UpdateDatabaseOperationStatus(ctx, generated.UpdateDatabaseOperationStatusParams{
		ID: op.ID, Status: string(to), ErrorSummary: pgutil.Text(errSummary),
	})
	if err != nil {
		return op, fmt.Errorf("update database operation status: %w", err)
	}
	return updated, nil
}

// captureHealthLabel opens a fresh direct connection, collects fast
// metrics, and computes a health label -- used both before and after
// execution (spec's "Post-operation verification: Reconnect, Check
// health, Check metrics..."). Returns "UNKNOWN" if the database can't be
// reached at all, never a fabricated healthy/unhealthy guess.
func (s *DatabaseOperationService) captureHealthLabel(ctx context.Context, conn DirectDatabaseConnection) string {
	if err := TestDirectConnection(ctx, conn); err != nil {
		return string(HealthOffline)
	}
	result, err := CollectDirectDatabaseMetrics(ctx, conn)
	if err != nil {
		return string(HealthUnknown)
	}
	maxMemory := detailInt64(result.Details, "max_memory_bytes")
	health := ComputeDatabaseHealth(result.Common, maxMemory, ConnCONNECTED, s.healthThresholds)
	return string(health)
}

// Run executes one PENDING database operation end to end (spec: Review ->
// Approve -> Execute -> Verify). Called only by DatabaseOperationWorker on
// its own goroutine. Every exit path leaves the operation in a terminal
// status.
func (s *DatabaseOperationService) Run(ctx context.Context, operationID uuid.UUID) {
	op, err := s.store.GetDatabaseOperationByID(ctx, operationID)
	if err != nil {
		return
	}
	db, err := s.store.GetDatabaseByID(ctx, op.DatabaseID)
	if err != nil || db.DeletedAt.Valid {
		s.fail(ctx, op, "Could not load the target database.")
		return
	}
	sink := newDatabaseOperationLogSink(ctx, s.store, operationID, s.logMaxBytes)

	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	deadline := time.Now().Add(s.operationTimeout)
	if _, err := s.store.SetDatabaseOperationTimeoutAt(opCtx, generated.SetDatabaseOperationTimeoutAtParams{ID: operationID, TimeoutAt: pgutil.Timestamptz(deadline)}); err != nil {
		sink.system("Warning: could not persist the operation deadline.")
	}

	// --- RUNNING: validation ---
	op, err = s.transition(opCtx, op, DBOpRunning, "")
	if err != nil {
		return
	}
	_ = s.audit.Log(opCtx, AuditEvent{
		UserID: uuidPtr(op.RequestedBy), Action: AuditDatabaseOperationStarted, ResourceType: "DATABASE", ResourceID: &db.ResourceID,
		Metadata: map[string]any{"database_operation_id": operationID, "operation_type": op.OperationType},
	})
	sink.system("Validating operation.")

	opType := DatabaseOperationType(op.OperationType)
	var params map[string]string
	_ = json.Unmarshal(op.Parameters, &params)

	report, precheckErr := s.RunPrecheck(opCtx, op.DatabaseID, opType, params, operationID)
	if precheckErr != nil || !report.AllPassed {
		msg := "Pre-flight checks failed."
		if precheckErr == nil {
			msg = summarizeFailedChecks(report)
		}
		sink.system(msg)
		s.fail(opCtx, op, msg)
		return
	}
	sink.system("Pre-flight checks passed.")

	username, password, credErr := s.credentials.GetCredential(opCtx, op.DatabaseID)
	if credErr != nil {
		msg := "No monitoring credential is configured for this database."
		sink.system(msg)
		s.fail(opCtx, op, msg)
		return
	}
	conn := s.buildConnection(db, username, password)

	sink.system("Capturing pre-operation health snapshot.")
	healthBefore := s.captureHealthLabel(opCtx, conn)
	sink.system("Health before: " + healthBefore)

	sink.system("Connecting to database.")
	sink.system("Executing operation: " + op.CommandPreview)
	resultSummary, resultDetail, execErr := ExecuteOperation(opCtx, conn, opType, params)

	if execErr != nil {
		if opCtx.Err() != nil {
			msg := "Operation timed out after " + s.operationTimeout.String() + "."
			sink.system(msg)
			s.timeout(ctx, op, msg)
			return
		}
		msg := safeErrorMessage(execErr)
		sink.system("Operation failed: " + msg)
		s.fail(ctx, op, msg)
		return
	}
	sink.system("Operation completed: " + resultSummary)

	// --- Post-operation verification ---
	sink.system("Reconnecting to verify database health.")
	healthAfter := s.captureHealthLabel(ctx, conn)
	sink.system("Health after: " + healthAfter)

	summary := resultSummary
	switch {
	case healthAfter == string(HealthCritical) || healthAfter == string(HealthOffline):
		summary = resultSummary + " Operation completed but the database requires attention (health: " + healthAfter + ")."
	case healthAfter == string(HealthWarning):
		summary = resultSummary + " Operation completed but the database is reporting a warning (health: " + healthAfter + ")."
	default:
		summary = resultSummary + " Operation successful; database is healthy."
	}

	detailJSON, _ := json.Marshal(resultDetail)
	updated, err := s.store.CompleteDatabaseOperation(ctx, generated.CompleteDatabaseOperationParams{
		ID: operationID, Status: string(DBOpSuccess), ResultSummary: pgutil.Text(summary), ResultDetail: detailJSON,
		HealthBefore: pgutil.Text(healthBefore), HealthAfter: pgutil.Text(healthAfter),
	})
	if err != nil {
		return
	}
	_ = s.audit.Log(ctx, AuditEvent{
		UserID: uuidPtr(updated.RequestedBy), Action: AuditDatabaseOperationCompleted, ResourceType: "DATABASE", ResourceID: &db.ResourceID,
		Metadata: map[string]any{"database_operation_id": operationID, "status": string(DBOpSuccess), "health_after": healthAfter},
	})
}

func (s *DatabaseOperationService) fail(ctx context.Context, op generated.DatabaseOperation, message string) {
	updated, err := s.transition(ctx, op, DBOpFailed, message)
	if err != nil {
		return
	}
	db, _ := s.store.GetDatabaseByID(ctx, op.DatabaseID)
	_ = s.audit.Log(ctx, AuditEvent{
		UserID: uuidPtr(updated.RequestedBy), Action: AuditDatabaseOperationFailed, ResourceType: "DATABASE", ResourceID: &db.ResourceID,
		Metadata: map[string]any{"database_operation_id": updated.ID, "status": string(DBOpFailed), "summary": message},
	})
}

func (s *DatabaseOperationService) timeout(ctx context.Context, op generated.DatabaseOperation, message string) {
	updated, err := s.transition(ctx, op, DBOpTimeout, message)
	if err != nil {
		return
	}
	db, _ := s.store.GetDatabaseByID(ctx, op.DatabaseID)
	_ = s.audit.Log(ctx, AuditEvent{
		UserID: uuidPtr(updated.RequestedBy), Action: AuditDatabaseOperationFailed, ResourceType: "DATABASE", ResourceID: &db.ResourceID,
		Metadata: map[string]any{"database_operation_id": updated.ID, "status": string(DBOpTimeout), "summary": message},
	})
}
