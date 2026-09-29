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

var (
	ErrRebootConfirmationReq   = errors.New("reboot requires explicit confirmation")
	ErrRebootNotRequired       = errors.New("this VM does not currently require a reboot; pass reason=ADMIN_REQUEST to reboot anyway")
	ErrRebootInvalidReason     = errors.New("invalid reboot reason")
	ErrRebootUpdateRunning     = errors.New("an update operation is currently running")
	ErrRebootAlreadyRunning    = errors.New("a reboot operation is already in progress for this VM")
	ErrRebootOperationNotFound = errors.New("reboot operation not found")
	ErrRebootCancelUnavailable = errors.New("cancellation is unavailable once the reboot command has been sent")
	ErrRebootChecksFailed      = errors.New("reboot readiness checks failed")
)

var validRebootReasons = map[string]bool{
	"KERNEL_UPDATE": true, "PACKAGE_UPDATE": true, "ADMIN_REQUEST": true, "OS_UPDATE": true, "OTHER": true,
}

// RebootExecutionService is the Step 11 orchestrator: Admin confirms ->
// revalidate -> transactional claim (locks both the update AND reboot
// exclusivity checks for this VM) -> async worker -> connect -> detect
// privilege -> send a backend-chosen reboot command -> expect SSH
// disconnect -> wait -> reconnect with backoff -> multi-signal verify ->
// rediscover. Reuses SSHService/RemoteExecutor (Step 5) and
// VMDiscoveryService/VMMonitoringService/PackageService/
// DockerDiscoveryService/OSUpdateService (Steps 5-9) wholesale for
// everything that isn't unique to reboot itself -- see docs/vm-reboot.md.
type RebootExecutionService struct {
	store      *repository.Store
	ssh        *SSHService
	executor   *RemoteExecutor
	discovery  *VMDiscoveryService
	monitoring *VMMonitoringService
	packages   *PackageService
	docker     *DockerDiscoveryService
	osUpdates  *OSUpdateService
	audit      *AuditService

	sshCommandTimeout    time.Duration
	rebootTimeout        time.Duration
	initialWait          time.Duration
	maxReconnectAttempts int32
	logMaxBytes          int64
}

// NewRebootExecutionService creates a RebootExecutionService.
func NewRebootExecutionService(
	store *repository.Store, ssh *SSHService, executor *RemoteExecutor,
	discovery *VMDiscoveryService, monitoring *VMMonitoringService, packages *PackageService,
	docker *DockerDiscoveryService, osUpdates *OSUpdateService, audit *AuditService,
	sshCommandTimeout, rebootTimeout, initialWait time.Duration, maxReconnectAttempts int32, logMaxBytes int64,
) *RebootExecutionService {
	return &RebootExecutionService{
		store: store, ssh: ssh, executor: executor, discovery: discovery, monitoring: monitoring,
		packages: packages, docker: docker, osUpdates: osUpdates, audit: audit,
		sshCommandTimeout: sshCommandTimeout, rebootTimeout: rebootTimeout, initialWait: initialWait,
		maxReconnectAttempts: maxReconnectAttempts, logMaxBytes: logMaxBytes,
	}
}

// RunPrecheck runs the read-only reboot-readiness checklist (spec #12/
// #13/#66) for resourceID -- never sends any command, safe to call
// repeatedly and standalone (POST /api/vms/:id/reboot/precheck) or as the
// first phase inside RequestReboot/Run.
func (s *RebootExecutionService) RunPrecheck(ctx context.Context, resourceID uuid.UUID, excludeRebootOperationID uuid.UUID) (PrecheckReport, error) {
	vm, err := s.store.GetVMByResourceID(ctx, resourceID)
	if err != nil {
		return PrecheckReport{}, fmt.Errorf("load vm: %w", err)
	}
	report := PrecheckReport{AllPassed: true}

	if hasCred, err := s.store.HasSSHCredential(ctx, resourceID); err != nil || !hasCred {
		report.add("ssh_configured", PrecheckFail, "No SSH credential is configured for this VM.")
	} else {
		report.add("ssh_configured", PrecheckPass, "SSH credential is configured.")
		client, connErr := s.ssh.Connect(ctx, resourceID)
		if outcomeErr := RecordConnectionOutcome(ctx, s.store, resourceID, vm.ID, connErr); outcomeErr != nil {
			report.add("vm_reachable", PrecheckUnknown, "Could not record connection outcome.")
		} else if connErr != nil {
			report.add("vm_reachable", PrecheckFail, "VM is not reachable: "+classifyConnectError(connErr).Message)
		} else {
			client.Close()
			report.add("vm_reachable", PrecheckPass, "VM is reachable over SSH.")
		}
	}

	// Cross-operation exclusivity display (spec #10/#12): a non-terminal
	// update blocks reboot, and vice versa -- the authoritative atomic
	// check happens inside the transactional claim in RequestReboot; this
	// is a read-only preview of the same fact.
	if _, err := s.store.GetRunningUpdateOperationByResource(ctx, generated.GetRunningUpdateOperationByResourceParams{
		ResourceID: pgutil.NullUUID(&resourceID),
	}); err == nil {
		report.add("no_update_running", PrecheckFail, "An update operation is currently running.")
	} else if errors.Is(err, pgx.ErrNoRows) {
		report.add("no_update_running", PrecheckPass, "No update operation currently running.")
	} else {
		report.add("no_update_running", PrecheckUnknown, "Could not determine whether an update operation is running.")
	}

	var excludeParam pgtype.UUID
	if excludeRebootOperationID != uuid.Nil {
		excludeParam = pgutil.NullUUID(&excludeRebootOperationID)
	}
	if _, err := s.store.GetActiveRebootForResourceLocked(ctx, generated.GetActiveRebootForResourceLockedParams{
		VmID: vm.ID, ExcludeRebootOperationID: excludeParam,
	}); err == nil {
		report.add("no_reboot_running", PrecheckFail, "A reboot operation is already in progress for this VM.")
	} else if errors.Is(err, pgx.ErrNoRows) {
		report.add("no_reboot_running", PrecheckPass, "No reboot operation currently in progress.")
	} else {
		report.add("no_reboot_running", PrecheckUnknown, "Could not determine whether a reboot is in progress.")
	}

	kernelRunning := pgutil.TextOrEmpty(vm.KernelVersion)
	kernelAvailable := pgutil.TextOrEmpty(vm.KernelAvailable)
	if kernelAvailable != "" && kernelAvailable != kernelRunning {
		report.add("kernel", PrecheckInfo, fmt.Sprintf("Running %s, installed %s.", kernelRunning, kernelAvailable))
	} else {
		report.add("kernel", PrecheckInfo, fmt.Sprintf("Running %s.", kernelRunning))
	}

	switch pgutil.TextOrEmpty(vm.RebootStatus) {
	case "REQUIRED":
		report.add("reboot_required", PrecheckPass, "Reboot is required.")
	case "NOT_REQUIRED":
		report.add("reboot_required", PrecheckInfo, "This VM does not currently require a reboot.")
	default:
		report.add("reboot_required", PrecheckUnknown, "Reboot requirement has not been detected yet.")
	}

	if vm.DockerInstalled {
		status := pgutil.TextOrEmpty(vm.DockerDaemonStatus)
		if status == "RUNNING" {
			report.add("docker", PrecheckPass, "Docker daemon is running.")
		} else {
			report.add("docker", PrecheckWarn, fmt.Sprintf("Docker daemon status: %s.", nonEmptyOr(status, "UNKNOWN")))
		}
	}

	if filesystems, err := s.store.ListLatestVMFilesystems(ctx, vm.ID); err == nil {
		for _, fs := range filesystems {
			if fs.MountPoint != "/" {
				continue
			}
			if fs.UsagePercent.Valid {
				report.add("disk_space", PrecheckInfo, fmt.Sprintf("Root filesystem: %.0f%% used.", fs.UsagePercent.Float64))
			}
			break
		}
	}

	return report, nil
}

// RequestReboot is the synchronous half of POST /api/vms/:id/reboot:
// validate confirmation/reason, revalidate readiness, and atomically
// claim the VM (lock plan -> check no active update AND no active reboot
// -> create reboot operation -> commit) -- all before any SSH activity.
// Returns immediately; Run does the actual work via the worker pool.
func (s *RebootExecutionService) RequestReboot(ctx context.Context, resourceID, userID uuid.UUID, reason string, confirmed bool) (generated.RebootOperation, error) {
	if !confirmed {
		return generated.RebootOperation{}, ErrRebootConfirmationReq
	}
	if reason == "" {
		reason = "ADMIN_REQUEST"
	}
	if !validRebootReasons[reason] {
		return generated.RebootOperation{}, ErrRebootInvalidReason
	}

	vm, err := s.store.GetVMByResourceID(ctx, resourceID)
	if err != nil {
		return generated.RebootOperation{}, fmt.Errorf("load vm: %w", err)
	}

	// spec #14: reject a reboot for a VM that doesn't need one, unless the
	// admin explicitly chose a manual reboot (ADMIN_REQUEST always allowed).
	if pgutil.TextOrEmpty(vm.RebootStatus) != "REQUIRED" && reason != "ADMIN_REQUEST" {
		return generated.RebootOperation{}, ErrRebootNotRequired
	}

	report, err := s.RunPrecheck(ctx, resourceID, uuid.Nil)
	if err != nil {
		return generated.RebootOperation{}, fmt.Errorf("precheck: %w", err)
	}
	if !report.AllPassed {
		for _, item := range report.Items {
			if item.Status != PrecheckFail {
				continue
			}
			switch item.Name {
			case "no_update_running":
				return generated.RebootOperation{}, ErrRebootUpdateRunning
			case "no_reboot_running":
				return generated.RebootOperation{}, ErrRebootAlreadyRunning
			}
		}
		return generated.RebootOperation{}, fmt.Errorf("%w: %s", ErrRebootChecksFailed, summarizeFailedChecks(report))
	}

	var op generated.RebootOperation
	err = s.store.WithTx(ctx, func(q *generated.Queries) error {
		if _, lockErr := q.GetActiveOperationForResourceLocked(ctx, pgutil.NullUUID(&resourceID)); lockErr == nil {
			return ErrRebootUpdateRunning
		} else if !errors.Is(lockErr, pgx.ErrNoRows) {
			return fmt.Errorf("check active update: %w", lockErr)
		}
		if _, lockErr := q.GetActiveRebootForResourceLocked(ctx, generated.GetActiveRebootForResourceLockedParams{VmID: vm.ID}); lockErr == nil {
			return ErrRebootAlreadyRunning
		} else if !errors.Is(lockErr, pgx.ErrNoRows) {
			return fmt.Errorf("check active reboot: %w", lockErr)
		}

		created, createErr := q.CreateRebootOperation(ctx, generated.CreateRebootOperationParams{
			VmID: vm.ID, CreatedBy: pgutil.NullUUID(&userID), Reason: reason,
		})
		if createErr != nil {
			return fmt.Errorf("create reboot operation: %w", createErr)
		}
		op = created
		return nil
	})
	if err != nil {
		return generated.RebootOperation{}, err
	}

	_ = s.audit.Log(ctx, AuditEvent{
		UserID: &userID, Action: AuditRebootRequested, ResourceType: "VM", ResourceID: &resourceID,
		Metadata: map[string]any{"reboot_operation_id": op.ID, "reason": reason},
	})
	return op, nil
}

// Cancel is only permitted before the reboot command has actually been
// sent (spec #51: "After REBOOT_SENT do not provide a cancel button --
// the VM is already rebooting").
func (s *RebootExecutionService) Cancel(ctx context.Context, operationID uuid.UUID) (generated.RebootOperation, error) {
	op, err := s.store.GetRebootOperationByID(ctx, operationID)
	if err != nil {
		return generated.RebootOperation{}, ErrRebootOperationNotFound
	}
	status := RebootStatus(op.Status)
	if status != RebootPending && status != RebootPrecheck {
		return op, ErrRebootCancelUnavailable
	}
	if err := ValidateRebootTransition(status, RebootCancelled); err != nil {
		return op, err
	}
	return s.store.UpdateRebootOperationStatus(ctx, generated.UpdateRebootOperationStatusParams{
		ID: operationID, Status: string(RebootCancelled), ErrorSummary: pgutil.Text("Cancelled by admin before the reboot command was sent."),
	})
}

// RecoverInterruptedRebootOperations marks any reboot left in a
// non-terminal state by an unclean prior shutdown as INTERRUPTED --
// called once at startup, before the HTTP server or worker pool starts.
// Never automatically resumes or re-sends a reboot command (spec: "no
// automatic retry, ever" / "no automatic second reboot").
func (s *RebootExecutionService) RecoverInterruptedRebootOperations(ctx context.Context) (int, error) {
	ops, err := s.store.ListNonTerminalRebootOperations(ctx)
	if err != nil {
		return 0, fmt.Errorf("list non-terminal reboot operations: %w", err)
	}
	const msg = "Backend stopped while this reboot was in progress. The VM's final state must be verified manually."
	for _, op := range ops {
		_, _ = s.store.UpdateRebootOperationStatus(ctx, generated.UpdateRebootOperationStatusParams{
			ID: op.ID, Status: string(RebootInterrupted), ErrorSummary: pgutil.Text(msg),
		})
	}
	return len(ops), nil
}
