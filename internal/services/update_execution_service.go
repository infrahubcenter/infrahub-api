package services

import (
	"context"
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

// Step-number constants for update_operation_steps, matching the spec's
// fixed 6-step (plus implicit "complete") progress checklist. The UI must
// only ever show a step as done once the backend has actually recorded it
// SUCCESS/FAILED here -- never fabricated progress.
const (
	StepPrecheck        int32 = 1
	StepConnect         int32 = 2
	StepRefreshMetadata int32 = 3
	StepUpdate          int32 = 4
	StepVerify          int32 = 5
	StepDiscovery       int32 = 6
)

var (
	ErrUpdatePlanNotReady      = errors.New("update plan must be READY before it can be executed")
	ErrUpdateAlreadyExecuting  = errors.New("this VM already has an update operation in progress")
	ErrUpdateVMRebooting       = errors.New("this VM is currently rebooting")
	ErrUpdateConfirmationReq   = errors.New("execution requires explicit confirmation")
	ErrUpdateTooManyPackages   = errors.New("update plan exceeds the maximum packages per plan")
	ErrUpdateOperationNotFound = errors.New("update operation not found")
	ErrUpdateCancelUnavailable = errors.New("cancellation is unavailable while package changes are in progress")
)

// ExecutionPrecheckFailedError wraps a fresh, failed revalidation result
// so the handler can render exactly which checks failed rather than a
// generic error.
type ExecutionPrecheckFailedError struct {
	Result ValidateResult
}

func (e ExecutionPrecheckFailedError) Error() string {
	return "update plan failed pre-execution revalidation"
}

// UpdateExecutionService is the Step 10 orchestrator: Recommendation ->
// Update Plan (Step 9) -> [this file] Revalidate -> Precheck -> Command ->
// SSH Execute -> Verify -> Rediscover. Every real VM-modifying action in
// this project lives here and nowhere else. Reuses SSHService/
// RemoteExecutor (Step 5), UpdatePlanService's prechecks (Step 9),
// VMDiscoveryService/VMMonitoringService/PackageService/
// DockerDiscoveryService/OSUpdateService (Steps 5-9) for everything that
// isn't unique to execution itself.
type UpdateExecutionService struct {
	store           *repository.Store
	ssh             *SSHService
	executor        *RemoteExecutor
	plans           *UpdatePlanService
	commandBuilders *UpdateCommandBuilderFactory
	discovery       *VMDiscoveryService
	monitoring      *VMMonitoringService
	packages        *PackageService
	docker          *DockerDiscoveryService
	osUpdates       *OSUpdateService
	audit           *AuditService

	sshCommandTimeout    time.Duration // short, fixed commands: precheck/connect/verify/discovery
	updateCommandTimeout time.Duration // UPDATE_COMMAND_TIMEOUT -- the package-manager command itself
	logMaxBytes          int64
	maxPackagesPerPlan   int32
}

// NewUpdateExecutionService creates an UpdateExecutionService.
func NewUpdateExecutionService(
	store *repository.Store, ssh *SSHService, executor *RemoteExecutor, plans *UpdatePlanService,
	discovery *VMDiscoveryService, monitoring *VMMonitoringService, packages *PackageService,
	docker *DockerDiscoveryService, osUpdates *OSUpdateService, audit *AuditService,
	sshCommandTimeout, updateCommandTimeout time.Duration, logMaxBytes int64, maxPackagesPerPlan int32,
) *UpdateExecutionService {
	return &UpdateExecutionService{
		store: store, ssh: ssh, executor: executor, plans: plans, commandBuilders: NewUpdateCommandBuilderFactory(),
		discovery: discovery, monitoring: monitoring, packages: packages, docker: docker, osUpdates: osUpdates, audit: audit,
		sshCommandTimeout: sshCommandTimeout, updateCommandTimeout: updateCommandTimeout,
		logMaxBytes: logMaxBytes, maxPackagesPerPlan: maxPackagesPerPlan,
	}
}

// RequestExecution is the synchronous half of POST /api/update-plans/:id/execute:
// authorize (done by the caller), validate confirmation, revalidate the
// plan against live evidence, and atomically claim the VM (transactional
// "lock plan -> validate -> check no active operation -> create operation
// -> plan status EXECUTING -> commit", spec's exact ordering) -- all
// before any SSH activity happens. Returns immediately; the actual
// execution runs on the worker pool via Enqueue.
func (s *UpdateExecutionService) RequestExecution(ctx context.Context, planID, userID uuid.UUID, confirmed bool) (generated.Operation, error) {
	if !confirmed {
		return generated.Operation{}, ErrUpdateConfirmationReq
	}

	plan, err := s.store.GetUpdatePlanByID(ctx, planID)
	if err != nil {
		return generated.Operation{}, err
	}
	if plan.Status != "READY" && plan.Status != "APPROVED" {
		return generated.Operation{}, ErrUpdatePlanNotReady
	}

	items, err := s.store.ListUpdatePlanItemsByPlan(ctx, planID)
	if err != nil {
		return generated.Operation{}, fmt.Errorf("list plan items: %w", err)
	}
	if int32(len(items)) > s.maxPackagesPerPlan {
		return generated.Operation{}, ErrUpdateTooManyPackages
	}

	vm, err := s.store.GetVMByID(ctx, plan.VmID)
	if err != nil {
		return generated.Operation{}, fmt.Errorf("load vm: %w", err)
	}

	// Revalidate immediately before claiming -- never execute solely
	// because a plan was approved earlier (spec). A precheck failure here
	// marks the plan STALE rather than executing a possibly-invalid plan.
	result, err := s.plans.ValidatePlan(ctx, planID)
	if err != nil {
		return generated.Operation{}, fmt.Errorf("revalidate plan: %w", err)
	}
	if !result.Report.AllPassed {
		_, _ = s.store.SetUpdatePlanStatus(ctx, generated.SetUpdatePlanStatusParams{ID: planID, Status: "STALE"})
		return generated.Operation{}, ExecutionPrecheckFailedError{Result: result}
	}

	builder := s.commandBuilders.New(PackageManagerType(pgutil.TextOrEmpty(vm.PackageManager)))
	var estimatedCommand string
	if builder != nil {
		names, isKernel := planItemNames(items)
		if cmd, ok := EstimatedExecutionCommand(builder, names, isKernel, pgutil.TextOrEmpty(vm.Username)); ok {
			estimatedCommand = cmd
		}
	}

	var op generated.Operation
	err = s.store.WithTx(ctx, func(q *generated.Queries) error {
		if _, lockErr := q.GetActiveOperationForResourceLocked(ctx, pgutil.NullUUID(&vm.ResourceID)); lockErr == nil {
			return ErrUpdateAlreadyExecuting
		} else if !errors.Is(lockErr, pgx.ErrNoRows) {
			return fmt.Errorf("check active operation: %w", lockErr)
		}
		// Cross-operation exclusivity (Step 11): a VM currently rebooting
		// must never also start an update -- checked inside the same
		// transaction as the update's own claim, mirroring how
		// RebootExecutionService.RequestReboot checks for an active update.
		if _, lockErr := q.GetActiveRebootForResourceLocked(ctx, generated.GetActiveRebootForResourceLockedParams{VmID: vm.ID}); lockErr == nil {
			return ErrUpdateVMRebooting
		} else if !errors.Is(lockErr, pgx.ErrNoRows) {
			return fmt.Errorf("check active reboot: %w", lockErr)
		}

		created, createErr := q.CreateUpdateOperation(ctx, generated.CreateUpdateOperationParams{
			ResourceID:     pgutil.NullUUID(&vm.ResourceID),
			OperationType:  "PACKAGE_UPDATE",
			RequestedBy:    pgutil.NullUUID(&userID),
			CommandPreview: pgutil.Text(estimatedCommand),
			UpdatePlanID:   pgutil.NullUUID(&planID),
		})
		if createErr != nil {
			return fmt.Errorf("create operation: %w", createErr)
		}
		op = created

		if _, stErr := q.SetUpdatePlanStatus(ctx, generated.SetUpdatePlanStatusParams{ID: planID, Status: "EXECUTING"}); stErr != nil {
			return fmt.Errorf("lock plan status: %w", stErr)
		}
		return nil
	})
	if err != nil {
		return generated.Operation{}, err
	}

	_ = s.audit.Log(ctx, AuditEvent{
		UserID: &userID, Action: AuditUpdateExecutionRequested, ResourceType: "VM", ResourceID: &vm.ResourceID,
		Metadata: map[string]any{"update_plan_id": planID, "operation_id": op.ID, "package_count": len(items)},
	})

	return op, nil
}

func planItemNames(items []generated.UpdatePlanItem) (names []string, anyKernel bool) {
	for _, it := range items {
		names = append(names, it.PackageName)
		if it.UpdateType == "KERNEL" {
			anyKernel = true
		}
	}
	return names, anyKernel
}

// logSink appends one line to operation_logs, tracking a byte budget so a
// single verbose command can never grow the DB row set unbounded (spec:
// UPDATE_LOG_MAX_BYTES). Once the budget is spent, further lines are
// dropped from persistence (a single SYSTEM note announces the
// truncation) -- this only affects the persisted transcript, never the
// exit code or verification logic downstream.
type logSink struct {
	ctx         context.Context
	store       *repository.Store
	operationID uuid.UUID
	seq         int32
	maxBytes    int64
	written     int64
	truncated   bool
}

func newLogSink(ctx context.Context, store *repository.Store, operationID uuid.UUID, maxBytes int64) *logSink {
	return &logSink{ctx: ctx, store: store, operationID: operationID, maxBytes: maxBytes}
}

func (l *logSink) system(message string) {
	l.append("SYSTEM", message)
}

func (l *logSink) line(stream, message string) {
	l.append(stream, message)
}

func (l *logSink) append(stream, message string) {
	if l.maxBytes > 0 && l.written >= l.maxBytes {
		if !l.truncated {
			l.truncated = true
			l.seq++
			_, _ = l.store.AppendOperationLog(l.ctx, generated.AppendOperationLogParams{
				OperationID: l.operationID, SequenceNumber: l.seq, Stream: "SYSTEM",
				Message: "Output truncated: this operation's log exceeded UPDATE_LOG_MAX_BYTES.",
			})
		}
		return
	}
	l.seq++
	l.written += int64(len(message))
	_, _ = l.store.AppendOperationLog(l.ctx, generated.AppendOperationLogParams{
		OperationID: l.operationID, SequenceNumber: l.seq, Stream: stream, Message: message,
	})
}

// transition validates and applies an operation status change, returning
// the updated row. exitCode/summary are optional (nil-able via pgtype
// zero values); callers pass sql.narg-shaped pgtype values directly.
func (s *UpdateExecutionService) transition(ctx context.Context, op generated.Operation, to OperationStatus, exitCode pgtype.Int4, summary string) (generated.Operation, error) {
	if err := ValidateOperationTransition(OperationStatus(op.Status), to); err != nil {
		return op, err
	}
	updated, err := s.store.UpdateOperationStatus(ctx, generated.UpdateOperationStatusParams{
		ID: op.ID, Status: string(to), ExitCode: exitCode, Summary: pgutil.Text(summary),
	})
	if err != nil {
		return op, fmt.Errorf("update operation status: %w", err)
	}
	return updated, nil
}

func (s *UpdateExecutionService) startStep(ctx context.Context, operationID uuid.UUID, step int32) {
	_, _ = s.store.StartOperationStep(ctx, generated.StartOperationStepParams{OperationID: operationID, StepNumber: step})
}

func (s *UpdateExecutionService) finishStep(ctx context.Context, operationID uuid.UUID, step int32, status string, exitCode pgtype.Int4, output, errSummary string) {
	_, _ = s.store.FinishOperationStep(ctx, generated.FinishOperationStepParams{
		OperationID: operationID, StepNumber: step, Status: status, ExitCode: exitCode,
		OutputSummary: pgutil.Text(output), ErrorSummary: pgutil.Text(errSummary),
	})
}

// planStatusForOperation maps a terminal operation outcome to the plan
// status it drives. Only SUCCESS yields COMPLETED and only PARTIAL yields
// PARTIAL; every other terminal outcome (FAILED/CANCELLED/INTERRUPTED)
// means this specific plan's one execution attempt did not cleanly
// succeed -- per the "no automatic retry, ever" rule, resuming requires a
// new plan regardless of which of those three outcomes occurred, so the
// plan is simply marked FAILED in all three cases.
func planStatusForOperation(status OperationStatus) string {
	switch status {
	case OpSuccess:
		return "COMPLETED"
	case OpPartial:
		return "PARTIAL"
	default:
		return "FAILED"
	}
}
