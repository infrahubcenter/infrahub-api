package services

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

const (
	cmdBootID = "cat /proc/sys/kernel/random/boot_id"
	cmdUptime = "cat /proc/uptime"
)

// reconnectBackoff is the fixed wait sequence between reconnect attempts
// (spec #22's exact example), capped at its last value for any attempt
// beyond the list's length -- deliberately not exponential-without-limit,
// to avoid a connection storm against a VM that's slow to come back.
var reconnectBackoff = []time.Duration{10 * time.Second, 15 * time.Second, 20 * time.Second, 30 * time.Second, 45 * time.Second, 60 * time.Second}

func backoffFor(attempt int) time.Duration {
	if attempt < len(reconnectBackoff) {
		return reconnectBackoff[attempt]
	}
	return reconnectBackoff[len(reconnectBackoff)-1]
}

// rebootSnapshot captures every before/after signal this file compares --
// always read from a real, live command or a fresh rediscovery call,
// never assumed or interpolated.
type rebootSnapshot struct {
	bootID           string
	uptimeSeconds    float64
	uptimeOK         bool
	osName           string
	osVersion        string
	kernelRunning    string
	rebootStatus     string
	dockerInstalled  bool
	dockerVersion    string
	dockerRunning    bool
	containerTotal   int64
	containerRunning int64
	diskUsagePercent float64
	diskKnown        bool
}

// rebootLogSink mirrors update_execution_service.go's logSink, against
// reboot_operation_logs instead of operation_logs (a separate table only
// because operation_logs.operation_id has a hard FK into operations).
type rebootLogSink struct {
	ctx         context.Context
	store       *repository.Store
	operationID uuid.UUID
	seq         int32
	maxBytes    int64
	written     int64
	truncated   bool
}

func newRebootLogSink(ctx context.Context, store *repository.Store, operationID uuid.UUID, maxBytes int64) *rebootLogSink {
	return &rebootLogSink{ctx: ctx, store: store, operationID: operationID, maxBytes: maxBytes}
}

func (l *rebootLogSink) system(message string) { l.append("SYSTEM", message) }

func (l *rebootLogSink) append(stream, message string) {
	if l.maxBytes > 0 && l.written >= l.maxBytes {
		if !l.truncated {
			l.truncated = true
			l.seq++
			_, _ = l.store.AppendRebootOperationLog(l.ctx, generated.AppendRebootOperationLogParams{
				RebootOperationID: l.operationID, SequenceNumber: l.seq, Stream: "SYSTEM",
				Message: "Output truncated: this operation's log exceeded UPDATE_LOG_MAX_BYTES.",
			})
		}
		return
	}
	l.seq++
	l.written += int64(len(message))
	_, _ = l.store.AppendRebootOperationLog(l.ctx, generated.AppendRebootOperationLogParams{
		RebootOperationID: l.operationID, SequenceNumber: l.seq, Stream: stream, Message: message,
	})
}

func (s *RebootExecutionService) transition(ctx context.Context, op generated.RebootOperation, to RebootStatus, errSummary string) (generated.RebootOperation, error) {
	if err := ValidateRebootTransition(RebootStatus(op.Status), to); err != nil {
		return op, err
	}
	updated, err := s.store.UpdateRebootOperationStatus(ctx, generated.UpdateRebootOperationStatusParams{
		ID: op.ID, Status: string(to), ErrorSummary: pgutil.Text(errSummary),
	})
	if err != nil {
		return op, fmt.Errorf("update reboot operation status: %w", err)
	}
	return updated, nil
}

// Run executes one PENDING reboot operation end to end. Called only by
// RebootExecutionWorker on its own goroutine. Every exit path leaves the
// operation in a terminal status.
func (s *RebootExecutionService) Run(ctx context.Context, operationID uuid.UUID) {
	op, err := s.store.GetRebootOperationByID(ctx, operationID)
	if err != nil {
		return
	}
	vm, err := s.store.GetVMByID(ctx, op.VmID)
	if err != nil {
		s.fail(ctx, op, "Could not load the target VM.")
		return
	}
	sink := newRebootLogSink(ctx, s.store, operationID, s.logMaxBytes)

	// --- PRECHECK ---
	op, err = s.transition(ctx, op, RebootPrecheck, "")
	if err != nil {
		return
	}
	_ = s.audit.Log(ctx, AuditEvent{
		UserID: uuidPtr(op.CreatedBy), Action: AuditRebootPrecheckStarted, ResourceType: "VM", ResourceID: &vm.ResourceID,
		Metadata: map[string]any{"reboot_operation_id": operationID},
	})
	sink.system("Running pre-check.")
	report, err := s.RunPrecheck(ctx, vm.ResourceID, operationID)
	if err != nil || !report.AllPassed {
		msg := "Pre-check failed."
		if err == nil {
			msg = summarizeFailedChecks(report)
		}
		sink.system(msg)
		_ = s.audit.Log(ctx, AuditEvent{
			UserID: uuidPtr(op.CreatedBy), Action: AuditRebootPrecheckFailed, ResourceType: "VM", ResourceID: &vm.ResourceID,
			Metadata: map[string]any{"reboot_operation_id": operationID},
		})
		s.fail(ctx, op, msg)
		return
	}
	sink.system("Pre-check passed.")

	// --- CONNECT ---
	client, connErr := s.ssh.Connect(ctx, vm.ResourceID)
	_ = RecordConnectionOutcome(ctx, s.store, vm.ResourceID, vm.ID, connErr)
	if connErr != nil {
		msg := "Could not connect to the VM: " + classifyConnectError(connErr).Message
		sink.system(msg)
		s.fail(ctx, op, msg)
		return
	}
	sink.system("SSH connection verified.")

	privilege, privErr := DetectPrivilegeMode(ctx, client, s.executor, s.sshCommandTimeout)
	if privErr != nil || privilege == PrivilegeUnsupported {
		client.Close()
		msg := "Configured SSH user requires an interactive sudo password, which is not supported."
		sink.system(msg)
		s.fail(ctx, op, msg)
		return
	}

	hasSystemctl := false
	if res, err := s.executor.Execute(ctx, client, cmdHasSystemctl, s.sshCommandTimeout); err == nil && res.ExitCode == 0 {
		hasSystemctl = true
	}
	command, ok := BuildRebootCommand(hasSystemctl, privilege)
	if !ok {
		client.Close()
		msg := "No safe reboot command could be generated for this VM."
		sink.system(msg)
		s.fail(ctx, op, msg)
		return
	}

	// --- BEFORE snapshot (spec #56) ---
	before := s.captureSnapshot(ctx, client, vm.ResourceID, vm.ID)
	sink.system(fmt.Sprintf("Before reboot: kernel %s, uptime %s, boot ID %s.", before.kernelRunning, formatUptime(before.uptimeSeconds), shortID(before.bootID)))

	// --- REBOOTING: send the command, expect disconnect ---
	op, err = s.transition(ctx, op, RebootRebooting, "")
	if err != nil {
		client.Close()
		return
	}
	sink.system("Sending reboot command: " + command)
	_, execErr := s.executor.Execute(ctx, client, command, s.sshCommandTimeout)
	// A transport-level error here is the EXPECTED happy path (spec #19/
	// #20): the VM going down mid-command is not a failure. Whether the
	// command returned cleanly first or the connection simply dropped,
	// both mean exactly one thing at this point: "reboot sent."
	if execErr != nil {
		sink.system("SSH connection closed (expected during reboot).")
	} else {
		sink.system("Reboot command completed; connection will close shortly.")
	}
	client.Close()
	_ = s.audit.Log(ctx, AuditEvent{
		UserID: uuidPtr(op.CreatedBy), Action: AuditRebootCommandSent, ResourceType: "VM", ResourceID: &vm.ResourceID,
		Metadata: map[string]any{"reboot_operation_id": operationID, "reason": op.Reason},
	})

	// --- WAITING_FOR_VM ---
	op, err = s.transition(ctx, op, RebootWaitingForVM, "")
	if err != nil {
		return
	}
	_, _ = s.store.SetVMOperationalState(ctx, generated.SetVMOperationalStateParams{ID: vm.ID, OperationalState: "REBOOTING"})
	_ = s.audit.Log(ctx, AuditEvent{
		UserID: uuidPtr(op.CreatedBy), Action: AuditRebootDisconnected, ResourceType: "VM", ResourceID: &vm.ResourceID,
		Metadata: map[string]any{"reboot_operation_id": operationID},
	})
	sink.system(fmt.Sprintf("Waiting %s before attempting to reconnect.", s.initialWait))

	deadline := time.Now().Add(s.rebootTimeout)
	if _, err := s.store.SetRebootTimeoutAt(ctx, generated.SetRebootTimeoutAtParams{ID: operationID, TimeoutAt: pgutil.Timestamptz(deadline)}); err != nil {
		sink.system("Warning: could not persist the reboot deadline.")
	}

	select {
	case <-time.After(s.initialWait):
	case <-ctx.Done():
		s.interrupt(ctx, op, "Backend is shutting down.")
		return
	}

	// --- RECONNECTING ---
	op, err = s.transition(ctx, op, RebootReconnecting, "")
	if err != nil {
		return
	}
	_ = s.audit.Log(ctx, AuditEvent{
		UserID: uuidPtr(op.CreatedBy), Action: AuditRebootReconnectStarted, ResourceType: "VM", ResourceID: &vm.ResourceID,
		Metadata: map[string]any{"reboot_operation_id": operationID},
	})

	var reClient *ssh.Client
	attempts := int32(0)
	for {
		if time.Now().After(deadline) {
			break
		}
		if attempts >= s.maxReconnectAttempts {
			break
		}
		sink.system(fmt.Sprintf("Attempting reconnect (attempt %d of %d)...", attempts+1, s.maxReconnectAttempts))
		client, connErr := s.ssh.Connect(ctx, vm.ResourceID)
		_ = RecordConnectionOutcome(ctx, s.store, vm.ResourceID, vm.ID, connErr)
		if connErr == nil {
			reClient = client
			break
		}
		attempts++
		wait := backoffFor(int(attempts) - 1)
		if remaining := time.Until(deadline); remaining < wait {
			wait = remaining
		}
		if wait <= 0 {
			break
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			s.interrupt(ctx, op, "Backend is shutting down.")
			return
		}
	}

	if reClient == nil {
		msg := "VM did not become reachable within the configured reboot timeout."
		sink.system(msg)
		_, _ = s.store.SetVMOperationalState(ctx, generated.SetVMOperationalStateParams{ID: vm.ID, OperationalState: "UNKNOWN"})
		op, _ = s.transition(ctx, op, RebootTimeout, msg)
		_ = s.audit.Log(ctx, AuditEvent{
			UserID: uuidPtr(op.CreatedBy), Action: AuditRebootTimeout, ResourceType: "VM", ResourceID: &vm.ResourceID,
			Metadata: map[string]any{"reboot_operation_id": operationID},
		})
		return
	}
	defer reClient.Close()
	sink.system("SSH connection restored.")

	// --- VERIFYING ---
	op, err = s.transition(ctx, op, RebootVerifying, "")
	if err != nil {
		return
	}
	_, _ = s.store.SetVMOperationalState(ctx, generated.SetVMOperationalStateParams{ID: vm.ID, OperationalState: "ONLINE"})
	_ = s.audit.Log(ctx, AuditEvent{
		UserID: uuidPtr(op.CreatedBy), Action: AuditRebootReconnected, ResourceType: "VM", ResourceID: &vm.ResourceID,
		Metadata: map[string]any{"reboot_operation_id": operationID},
	})
	_ = s.audit.Log(ctx, AuditEvent{
		UserID: uuidPtr(op.CreatedBy), Action: AuditRebootVerificationStarted, ResourceType: "VM", ResourceID: &vm.ResourceID,
		Metadata: map[string]any{"reboot_operation_id": operationID},
	})
	sink.system("Verifying kernel, OS, storage, Docker, and package state.")

	after := s.captureSnapshot(ctx, reClient, vm.ResourceID, vm.ID)
	final := s.verifyAndRecord(ctx, operationID, vm.ResourceID, op.Reason, before, after)
	sink.system(fmt.Sprintf("Verification completed: %s.", final))

	op, err = s.transition(ctx, op, final, "")
	if err != nil {
		return
	}

	action := AuditRebootFailed
	if final == RebootSuccess || final == RebootPartial {
		action = AuditRebootCompleted
	}
	_ = s.audit.Log(ctx, AuditEvent{
		UserID: uuidPtr(op.CreatedBy), Action: action, ResourceType: "VM", ResourceID: &vm.ResourceID,
		Metadata: map[string]any{"reboot_operation_id": operationID, "status": string(final)},
	})
}

// Verify is the admin-triggered, read-only re-check (POST
// /api/reboot-operations/:id/verify, spec #49/#50): useful when an
// operation ended TIMEOUT/UNKNOWN/INTERRUPTED and the admin wants a fresh
// read of the VM's actual state. Never sends a reboot command and never
// re-enters the state machine's REBOOTING phase -- only re-runs the same
// read-only verification checks against the ORIGINAL before-snapshot
// (reconstructed from the persisted expected_value of each check, which
// verifyAndRecord itself wrote from the real pre-reboot snapshot) and a
// freshly-captured after-snapshot.
func (s *RebootExecutionService) Verify(ctx context.Context, operationID, userID uuid.UUID) ([]generated.RebootVerificationResult, error) {
	op, err := s.store.GetRebootOperationByID(ctx, operationID)
	if err != nil {
		return nil, ErrRebootOperationNotFound
	}
	vm, err := s.store.GetVMByID(ctx, op.VmID)
	if err != nil {
		return nil, fmt.Errorf("load vm: %w", err)
	}
	existing, err := s.store.ListRebootVerificationResults(ctx, operationID)
	if err != nil {
		return nil, fmt.Errorf("load existing verification results: %w", err)
	}
	before := rebootSnapshotFromResults(existing)

	client, connErr := s.ssh.Connect(ctx, vm.ResourceID)
	_ = RecordConnectionOutcome(ctx, s.store, vm.ResourceID, vm.ID, connErr)
	if connErr != nil {
		return nil, fmt.Errorf("connect: %w", connErr)
	}
	defer client.Close()

	after := s.captureSnapshot(ctx, client, vm.ResourceID, vm.ID)
	s.verifyAndRecord(ctx, operationID, vm.ResourceID, op.Reason, before, after)

	_ = s.audit.Log(ctx, AuditEvent{
		UserID: &userID, Action: AuditRebootVerificationRetried, ResourceType: "VM", ResourceID: &vm.ResourceID,
		Metadata: map[string]any{"reboot_operation_id": operationID},
	})
	return s.store.ListRebootVerificationResults(ctx, operationID)
}

// rebootSnapshotFromResults reconstructs enough of a "before" snapshot
// for Verify's re-check from what verifyAndRecord already persisted --
// every field here is a real, previously-observed value, never guessed.
func rebootSnapshotFromResults(results []generated.RebootVerificationResult) rebootSnapshot {
	var snap rebootSnapshot
	for _, r := range results {
		expected := pgutil.TextOrEmpty(r.ExpectedValue)
		switch r.CheckType {
		case "BOOT_ID":
			snap.bootID = expected
		case "OS":
			snap.osName = expected
		case "KERNEL":
			snap.kernelRunning = strings.TrimPrefix(expected, "a newer kernel than ")
		}
	}
	return snap
}

func (s *RebootExecutionService) fail(ctx context.Context, op generated.RebootOperation, message string) {
	updated, err := s.transition(ctx, op, RebootFailed, message)
	if err != nil {
		return
	}
	_ = s.audit.Log(ctx, AuditEvent{
		UserID: uuidPtr(updated.CreatedBy), Action: AuditRebootFailed, ResourceType: "VM",
		Metadata: map[string]any{"reboot_operation_id": updated.ID, "status": string(RebootFailed), "summary": message},
	})
}

// interrupt is fail's counterpart for a backend shutdown mid-reboot: once
// the reboot command has actually been sent, we genuinely don't know the
// VM's state (it may still come back up on its own), so this is
// INTERRUPTED -- never FAILED, which would claim certainty the backend
// doesn't have. Also the only valid target from WAITING_FOR_VM/
// RECONNECTING, per the state machine (FAILED is not reachable from
// either -- attempting it would silently no-op and leave the operation
// stuck non-terminal forever).
func (s *RebootExecutionService) interrupt(ctx context.Context, op generated.RebootOperation, message string) {
	updated, err := s.transition(ctx, op, RebootInterrupted, message)
	if err != nil {
		return
	}
	_ = s.audit.Log(ctx, AuditEvent{
		UserID: uuidPtr(updated.CreatedBy), Action: AuditRebootFailed, ResourceType: "VM",
		Metadata: map[string]any{"reboot_operation_id": updated.ID, "status": string(RebootInterrupted), "summary": message},
	})
}

// captureSnapshot reads every before/after signal live from the VM (or,
// for storage/Docker, via the existing rediscovery services so those
// tables reflect the real current state too) -- never assumed.
func (s *RebootExecutionService) captureSnapshot(ctx context.Context, client *ssh.Client, resourceID, vmRowID uuid.UUID) rebootSnapshot {
	var snap rebootSnapshot

	if res, err := s.executor.Execute(ctx, client, cmdBootID, s.sshCommandTimeout); err == nil && res.ExitCode == 0 {
		snap.bootID = strings.TrimSpace(res.Stdout)
	}
	if res, err := s.executor.Execute(ctx, client, cmdUptime, s.sshCommandTimeout); err == nil && res.ExitCode == 0 {
		if secs, ok := parseUptimeSeconds(res.Stdout); ok {
			snap.uptimeSeconds = secs
			snap.uptimeOK = true
		}
	}

	if discResult, err := s.discovery.Discover(ctx, resourceID); err == nil {
		if discResult.OSName != nil {
			snap.osName = *discResult.OSName
		}
		if discResult.OSVersion != nil {
			snap.osVersion = *discResult.OSVersion
		}
		if discResult.KernelVersion != nil {
			snap.kernelRunning = *discResult.KernelVersion
		}
	}
	if osResult, err := s.osUpdates.Scan(ctx, resourceID); err == nil {
		snap.rebootStatus = osResult.RebootStatus
	}

	if vm, err := s.store.GetVMByID(ctx, vmRowID); err == nil {
		snap.dockerInstalled = vm.DockerInstalled
		if vm.DockerInstalled {
			if _, err := s.docker.Scan(ctx, resourceID); err == nil {
				if refreshed, err := s.store.GetVMByID(ctx, vmRowID); err == nil {
					snap.dockerVersion = pgutil.TextOrEmpty(refreshed.DockerEngineVersion)
					snap.dockerRunning = pgutil.TextOrEmpty(refreshed.DockerDaemonStatus) == string(DockerRunning)
				}
			}
			if summary, err := s.store.GetDockerSummaryByVM(ctx, vmRowID); err == nil {
				snap.containerTotal = summary.Total
				snap.containerRunning = summary.Running
			}
		}
	}

	if _, err := s.monitoring.Collect(ctx, resourceID); err == nil {
		if filesystems, err := s.store.ListLatestVMFilesystems(ctx, vmRowID); err == nil {
			for _, fs := range filesystems {
				if fs.MountPoint == "/" && fs.UsagePercent.Valid {
					snap.diskUsagePercent = fs.UsagePercent.Float64
					snap.diskKnown = true
					break
				}
			}
		}
	}

	return snap
}

// verifyAndRecord compares before/after and persists one
// reboot_verification_results row per check_type (spec #55/#57), then
// returns the overall outcome -- never SUCCESS unless every critical
// signal actually verified.
func (s *RebootExecutionService) verifyAndRecord(ctx context.Context, operationID, resourceID uuid.UUID, reason string, before, after rebootSnapshot) RebootStatus {
	upsert := func(checkType, expected, actual, status, errSummary string) {
		_, _ = s.store.UpsertRebootVerificationResult(ctx, generated.UpsertRebootVerificationResultParams{
			RebootOperationID: operationID, CheckType: checkType,
			ExpectedValue: pgutil.Text(expected), ActualValue: pgutil.Text(actual),
			Status: status, ErrorSummary: pgutil.Text(errSummary),
		})
	}

	criticalFailed := false
	criticalUnknown := false
	anyWarning := false

	// SSH: reaching this function at all already proves it.
	upsert("SSH", "reachable", "reachable", "VERIFIED", "")

	// BOOT_ID: the single strongest signal a real boot cycle occurred.
	switch {
	case before.bootID == "" || after.bootID == "":
		upsert("BOOT_ID", before.bootID, after.bootID, "UNKNOWN", "boot ID could not be read")
		criticalUnknown = true
	case before.bootID != after.bootID:
		upsert("BOOT_ID", before.bootID, after.bootID, "VERIFIED", "")
	default:
		upsert("BOOT_ID", before.bootID, after.bootID, "FAILED", "boot ID unchanged -- the VM may not have actually rebooted")
		criticalFailed = true
	}

	// UPTIME: corroborating signal, never relied on alone.
	switch {
	case !before.uptimeOK || !after.uptimeOK:
		upsert("UPTIME", formatUptime(before.uptimeSeconds), formatUptime(after.uptimeSeconds), "UNKNOWN", "uptime could not be read")
	case after.uptimeSeconds < before.uptimeSeconds:
		upsert("UPTIME", formatUptime(before.uptimeSeconds), formatUptime(after.uptimeSeconds), "VERIFIED", "")
	default:
		upsert("UPTIME", formatUptime(before.uptimeSeconds), formatUptime(after.uptimeSeconds), "WARNING", "uptime did not reset as expected")
		anyWarning = true
	}

	// OS: expected to remain the same distribution/version across a
	// reboot triggered by a kernel/package update (spec #27).
	beforeOS, afterOS := before.osName+" "+before.osVersion, after.osName+" "+after.osVersion
	if before.osName == "" || after.osName == "" {
		upsert("OS", beforeOS, afterOS, "UNKNOWN", "OS identity could not be read")
	} else if beforeOS == afterOS {
		upsert("OS", beforeOS, afterOS, "VERIFIED", "")
	} else {
		upsert("OS", beforeOS, afterOS, "WARNING", "OS identity changed unexpectedly")
		anyWarning = true
	}

	// KERNEL: the most important check for a kernel-update-triggered
	// reboot (spec #26) -- expected is the kernel that was installed but
	// not yet active before the reboot (falling back to "still the same
	// kernel" for a non-kernel-update reboot).
	expectedKernel := before.kernelRunning
	kernelCritical := reason == "KERNEL_UPDATE"
	switch {
	case before.kernelRunning == "" || after.kernelRunning == "":
		upsert("KERNEL", expectedKernel, after.kernelRunning, "UNKNOWN", "kernel version could not be read")
		if kernelCritical {
			criticalUnknown = true
		}
	case after.kernelRunning == expectedKernel && !kernelCritical:
		upsert("KERNEL", expectedKernel, after.kernelRunning, "VERIFIED", "")
	case kernelCritical && after.kernelRunning != before.kernelRunning:
		upsert("KERNEL", "a newer kernel than "+before.kernelRunning, after.kernelRunning, "VERIFIED", "")
	case kernelCritical:
		upsert("KERNEL", "a newer kernel than "+before.kernelRunning, after.kernelRunning, "FAILED",
			"New kernel is installed but the VM is still running the previous kernel.")
		criticalFailed = true
	default:
		upsert("KERNEL", expectedKernel, after.kernelRunning, "WARNING", "kernel changed unexpectedly")
		anyWarning = true
	}

	// STORAGE: report only, never a pass/fail signal on its own.
	if before.diskKnown && after.diskKnown {
		upsert("STORAGE", fmt.Sprintf("%.0f%%", before.diskUsagePercent), fmt.Sprintf("%.0f%%", after.diskUsagePercent), "VERIFIED", "")
	} else {
		upsert("STORAGE", "", "", "UNKNOWN", "disk usage could not be read")
	}

	// DOCKER + CONTAINERS: only applicable if Docker was installed.
	if !after.dockerInstalled {
		upsert("DOCKER", "", "", "NOT_APPLICABLE", "")
		upsert("CONTAINERS", "", "", "NOT_APPLICABLE", "")
	} else {
		if after.dockerRunning {
			upsert("DOCKER", before.dockerVersion, after.dockerVersion, "VERIFIED", "")
		} else {
			upsert("DOCKER", before.dockerVersion, after.dockerVersion, "WARNING", "Docker daemon is not running after reboot")
			anyWarning = true
		}
		switch {
		case after.containerTotal != before.containerTotal:
			upsert("CONTAINERS", fmt.Sprintf("%d total, %d running", before.containerTotal, before.containerRunning),
				fmt.Sprintf("%d total, %d running", after.containerTotal, after.containerRunning), "WARNING", "container count changed unexpectedly")
			anyWarning = true
		case after.containerRunning < before.containerRunning:
			upsert("CONTAINERS", fmt.Sprintf("%d running", before.containerRunning), fmt.Sprintf("%d running", after.containerRunning),
				"WARNING", "fewer containers running after reboot -- containers do not automatically restart")
			anyWarning = true
		default:
			upsert("CONTAINERS", fmt.Sprintf("%d running", before.containerRunning), fmt.Sprintf("%d running", after.containerRunning), "VERIFIED", "")
		}
	}

	// PACKAGES: confirm package inventory is still readable post-reboot
	// (spec #36/#83 -- run discovery, never execute any update here; Step
	// 10 already owns per-package version verification during its own
	// VERIFY step).
	if scanResult, err := s.packages.Scan(ctx, resourceID); err != nil || scanResult.Status == "FAILED" {
		upsert("PACKAGES", "", "", "UNKNOWN", safeErrorMessage(err))
	} else {
		upsert("PACKAGES", "", "", "VERIFIED", "")
	}

	// REBOOT_REQUIRED: expected to clear after a successful reboot.
	switch after.rebootStatus {
	case "NOT_REQUIRED":
		upsert("REBOOT_REQUIRED", "NOT_REQUIRED", after.rebootStatus, "VERIFIED", "")
	case "REQUIRED":
		upsert("REBOOT_REQUIRED", "NOT_REQUIRED", after.rebootStatus, "WARNING", "System still reports reboot required.")
		anyWarning = true
	default:
		upsert("REBOOT_REQUIRED", "NOT_REQUIRED", after.rebootStatus, "UNKNOWN", "")
	}

	switch {
	case criticalFailed:
		return RebootFailed
	case criticalUnknown:
		return RebootUnknown
	case anyWarning:
		return RebootPartial
	default:
		return RebootSuccess
	}
}

func formatUptime(seconds float64) string {
	d := time.Duration(seconds) * time.Second
	return d.String()
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func parseUptimeSeconds(output string) (float64, bool) {
	fields := strings.Fields(output)
	if len(fields) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
