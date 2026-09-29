package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/ssh"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
)

// Version-query commands mirror package_manager_impl.go's exact
// aptListInstalledCmd/rpmListInstalledCmd format strings (reusing
// ParseDpkgQuery/ParseRPMQA below), scoped to only the packages this
// operation touched instead of every installed package. Package names
// here have already passed ValidatePackageNamesForExecution, the same
// allowlist regex that makes the base update command injection-safe.
const (
	dpkgVersionQueryCmd = `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' `
	rpmVersionQueryCmd  = `rpm -q --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SUMMARY}\n' `
)

// Run executes one PENDING update operation end to end: precheck, connect,
// refresh metadata, run the update command, verify, rediscover. Called
// only by UpdateExecutionWorker on its own goroutine -- never from an HTTP
// handler directly, since this can run for up to UPDATE_COMMAND_TIMEOUT.
// Every exit path leaves the operation and its linked plan in a terminal
// status; Run never returns with either left non-terminal.
func (s *UpdateExecutionService) Run(ctx context.Context, operationID uuid.UUID) {
	op, err := s.store.GetOperationByID(ctx, operationID)
	if err != nil {
		return // nothing to update if the row itself can't be loaded
	}
	if !op.UpdatePlanID.Valid {
		return // defensive: every execution-created operation is plan-linked
	}
	planID := pgutil.UUID(op.UpdatePlanID)
	sink := newLogSink(ctx, s.store, operationID, s.logMaxBytes)

	plan, err := s.store.GetUpdatePlanByID(ctx, planID)
	if err != nil {
		s.fail(ctx, op, planID, "Could not load the update plan for this operation.")
		return
	}
	items, err := s.store.ListUpdatePlanItemsByPlan(ctx, planID)
	if err != nil || len(items) == 0 {
		s.fail(ctx, op, planID, "Could not load the selected packages for this plan.")
		return
	}
	vm, err := s.store.GetVMByID(ctx, plan.VmID)
	if err != nil {
		s.fail(ctx, op, planID, "Could not load the target VM.")
		return
	}

	// --- Step 1: PRECHECK -- full fresh revalidation, real evidence only ---
	_, _ = s.store.CreateOperationStep(ctx, generated.CreateOperationStepParams{OperationID: operationID, StepNumber: StepPrecheck, StepType: "PRECHECK"})
	s.startStep(ctx, operationID, StepPrecheck)
	sink.system("Running pre-execution checks.")
	result, err := s.plans.ValidatePlanForExecution(ctx, planID, operationID)
	if err != nil || !result.Report.AllPassed {
		msg := "Pre-execution checks failed."
		if err == nil {
			msg = summarizeFailedChecks(result.Report)
		}
		sink.system(msg)
		s.finishStep(ctx, operationID, StepPrecheck, "FAILED", pgtype.Int4{}, "", msg)
		_ = s.audit.Log(ctx, AuditEvent{
			UserID: uuidPtr(op.RequestedBy), Action: AuditUpdatePrecheckFailed, ResourceType: "VM", ResourceID: uuidPtr(op.ResourceID),
			Metadata: map[string]any{"update_plan_id": planID, "operation_id": operationID},
		})
		s.fail(ctx, op, planID, msg)
		return
	}
	s.finishStep(ctx, operationID, StepPrecheck, "SUCCESS", pgtype.Int4{}, "All prechecks passed.", "")

	// --- Step 2: CONNECT -- one persistent SSH client reused through the
	// update command; also where privilege is freshly detected (never
	// trusted from a stale vms.privilege_mode cache). ---
	_, _ = s.store.CreateOperationStep(ctx, generated.CreateOperationStepParams{OperationID: operationID, StepNumber: StepConnect, StepType: "CONNECT"})
	s.startStep(ctx, operationID, StepConnect)
	op, err = s.transition(ctx, op, OpConnecting, pgtype.Int4{}, "")
	if err != nil {
		s.finishStep(ctx, operationID, StepConnect, "FAILED", pgtype.Int4{}, "", err.Error())
		s.fail(ctx, op, planID, "Internal state error before connecting.")
		return
	}
	client, connErr := s.ssh.Connect(ctx, vm.ResourceID)
	_ = RecordConnectionOutcome(ctx, s.store, vm.ResourceID, vm.ID, connErr)
	if connErr != nil {
		msg := "Could not connect to the VM: " + classifyConnectError(connErr).Message
		sink.system(msg)
		s.finishStep(ctx, operationID, StepConnect, "FAILED", pgtype.Int4{}, "", msg)
		op, _ = s.transition(ctx, op, OpFailed, pgtype.Int4{}, msg)
		s.settlePlanAndAudit(ctx, op, planID, msg)
		return
	}
	defer client.Close()

	privilege, privErr := DetectPrivilegeMode(ctx, client, s.executor, s.sshCommandTimeout)
	_, _ = s.store.SetVMPrivilegeMode(ctx, generated.SetVMPrivilegeModeParams{ID: vm.ID, PrivilegeMode: pgutil.Text(string(privilege))})
	if privErr != nil || privilege == PrivilegeUnsupported {
		msg := "Configured SSH user requires an interactive sudo password, which is not supported."
		sink.system(msg)
		s.finishStep(ctx, operationID, StepConnect, "FAILED", pgtype.Int4{}, "", msg)
		op, _ = s.transition(ctx, op, OpFailed, pgtype.Int4{}, msg)
		s.settlePlanAndAudit(ctx, op, planID, msg)
		return
	}
	sink.system(fmt.Sprintf("Connected. Detected privilege mode: %s.", privilege))
	s.finishStep(ctx, operationID, StepConnect, "SUCCESS", pgtype.Int4{}, "Connected via SSH.", "")

	pmType := PackageManagerType(pgutil.TextOrEmpty(vm.PackageManager))
	builder := s.commandBuilders.New(pmType)
	if builder == nil {
		msg := "No supported package manager is available for execution."
		sink.system(msg)
		op, _ = s.transition(ctx, op, OpFailed, pgtype.Int4{}, msg)
		s.settlePlanAndAudit(ctx, op, planID, msg)
		return
	}
	names, isKernel := planItemNames(items)
	if err := ValidatePackageNamesForExecution(names); err != nil {
		msg := "One or more selected package names failed validation."
		sink.system(msg)
		op, _ = s.transition(ctx, op, OpFailed, pgtype.Int4{}, msg)
		s.settlePlanAndAudit(ctx, op, planID, msg)
		return
	}
	command, ok := BuildExecutionCommand(builder, names, isKernel, privilege)
	if !ok {
		msg := "No executable command could be generated for the selected packages."
		sink.system(msg)
		op, _ = s.transition(ctx, op, OpFailed, pgtype.Int4{}, msg)
		s.settlePlanAndAudit(ctx, op, planID, msg)
		return
	}
	hash := HashCommand(command)
	_, _ = s.store.SetOperationCommandHash(ctx, generated.SetOperationCommandHashParams{ID: operationID, CommandHash: pgutil.Text(hash)})

	// --- Step 3: REFRESH_METADATA -- best-effort, never fatal to the
	// overall operation (Step 7's documented non-root PARTIAL outcome is
	// an acceptable, pre-existing result here). ---
	_, _ = s.store.CreateOperationStep(ctx, generated.CreateOperationStepParams{OperationID: operationID, StepNumber: StepRefreshMetadata, StepType: "REFRESH_METADATA"})
	s.startStep(ctx, operationID, StepRefreshMetadata)
	refreshResult, refreshErr := s.packages.RefreshUpdates(ctx, vm.ResourceID)
	if refreshErr != nil {
		sink.system("Package metadata refresh failed: " + safeErrorMessage(refreshErr))
		s.finishStep(ctx, operationID, StepRefreshMetadata, "FAILED", pgtype.Int4{}, "", safeErrorMessage(refreshErr))
	} else {
		sink.system(fmt.Sprintf("Package metadata refresh: %s.", refreshResult.Status))
		s.finishStep(ctx, operationID, StepRefreshMetadata, "SUCCESS", pgtype.Int4{}, string(refreshResult.Status), "")
	}

	// --- Step 4: UPDATE -- the one command that actually modifies the VM ---
	_, _ = s.store.CreateOperationStep(ctx, generated.CreateOperationStepParams{OperationID: operationID, StepNumber: StepUpdate, StepType: "UPDATE"})
	s.startStep(ctx, operationID, StepUpdate)
	op, err = s.transition(ctx, op, OpRunning, pgtype.Int4{}, "")
	if err != nil {
		s.fail(ctx, op, planID, "Internal state error before executing the update command.")
		return
	}
	sink.system("Executing: " + command)
	execResult, execErr := s.executor.ExecuteStreaming(ctx, client, command, s.updateCommandTimeout, func(stream, line string) {
		sink.line(stream, line)
	})

	disconnected := false
	if execErr != nil {
		if sshErr, isTimeout := execErr.(*SSHError); isTimeout && sshErr.Code == ErrCodeTimeout {
			msg := fmt.Sprintf("Update command timed out after %s.", s.updateCommandTimeout)
			sink.system(msg)
			s.finishStep(ctx, operationID, StepUpdate, "FAILED", pgtype.Int4{}, "", msg)
			op, _ = s.transition(ctx, op, OpFailed, pgtype.Int4{}, msg)
			s.settlePlanAndAudit(ctx, op, planID, msg)
			return
		}
		// Transport-level failure mid-command (e.g. the SSH connection
		// dropped). Never assume the update failed -- the remote command
		// may still be running or may have completed. Proceed to
		// verification instead of failing outright (spec: "never assume
		// failure -- verify actual state").
		disconnected = true
		sink.system("SSH connection was lost during command execution. Reconnecting to verify actual VM state (never assuming success or failure).")
		s.finishStep(ctx, operationID, StepUpdate, "FAILED", pgtype.Int4{}, "", "SSH connection lost mid-command.")
	} else {
		sink.system(fmt.Sprintf("Command exited with code %d.", execResult.ExitCode))
		status := "SUCCESS"
		if execResult.ExitCode != 0 {
			status = "FAILED"
		}
		s.finishStep(ctx, operationID, StepUpdate, status, pgutil.Int4(int32(execResult.ExitCode)), fmt.Sprintf("Exit code %d.", execResult.ExitCode), "")
	}

	// --- Step 5: VERIFY -- never trust the exit code alone ---
	op, err = s.transition(ctx, op, OpVerifying, pgtype.Int4{}, "")
	if err != nil {
		s.fail(ctx, op, planID, "Internal state error before verification.")
		return
	}
	_, _ = s.store.CreateOperationStep(ctx, generated.CreateOperationStepParams{OperationID: operationID, StepNumber: StepVerify, StepType: "VERIFY"})
	s.startStep(ctx, operationID, StepVerify)

	verifyClient := client
	if disconnected {
		sink.system("Reconnecting for post-update verification.")
		reClient, reErr := s.ssh.Connect(ctx, vm.ResourceID)
		_ = RecordConnectionOutcome(ctx, s.store, vm.ResourceID, vm.ID, reErr)
		if reErr != nil {
			msg := "Could not reconnect after the update command. The final VM state could not be determined and must be verified manually."
			sink.system(msg)
			s.finishStep(ctx, operationID, StepVerify, "FAILED", pgtype.Int4{}, "", msg)
			op, _ = s.transition(ctx, op, OpInterrupted, execCodeOrEmpty(execErr, execResult), msg)
			s.settlePlanAndAudit(ctx, op, planID, msg)
			return
		}
		defer reClient.Close()
		verifyClient = reClient
	}

	verified, failed, unknown := s.verifyPackages(ctx, verifyClient, operationID, pmType, items)
	total := len(items)
	summary := fmt.Sprintf("%d of %d package(s) verified updated (%d failed, %d unknown).", verified, total, failed, unknown)
	sink.system(summary)
	s.finishStep(ctx, operationID, StepVerify, "SUCCESS", pgtype.Int4{}, summary, "")

	var final OperationStatus
	switch {
	case verified == total:
		final = OpSuccess
	case verified > 0:
		final = OpPartial
	default:
		final = OpFailed
	}
	op, err = s.transition(ctx, op, final, execCodeOrEmpty(execErr, execResult), summary)
	if err != nil {
		return
	}

	// --- Step 6: DISCOVERY -- rediscover real VM state, reusing existing
	// services wholesale; never duplicated here. Best-effort: none of
	// these can change the already-decided operation status above. ---
	_, _ = s.store.CreateOperationStep(ctx, generated.CreateOperationStepParams{OperationID: operationID, StepNumber: StepDiscovery, StepType: "DISCOVERY"})
	s.startStep(ctx, operationID, StepDiscovery)
	var discoveryNotes []string
	if _, derr := s.discovery.Discover(ctx, vm.ResourceID); derr != nil {
		discoveryNotes = append(discoveryNotes, "VM discovery: "+safeErrorMessage(derr))
	}
	if _, merr := s.monitoring.Collect(ctx, vm.ResourceID); merr != nil {
		discoveryNotes = append(discoveryNotes, "Monitoring: "+safeErrorMessage(merr))
	}
	if _, perr := s.packages.Scan(ctx, vm.ResourceID); perr != nil {
		discoveryNotes = append(discoveryNotes, "Package rescan: "+safeErrorMessage(perr))
	}
	if s.osUpdates != nil {
		if _, oerr := s.osUpdates.Scan(ctx, vm.ResourceID); oerr != nil {
			discoveryNotes = append(discoveryNotes, "OS/kernel/reboot rescan: "+safeErrorMessage(oerr))
		}
	}
	if s.docker != nil && anyDockerRelatedPackage(names) {
		if _, dkerr := s.docker.Scan(ctx, vm.ResourceID); dkerr != nil {
			discoveryNotes = append(discoveryNotes, "Docker rediscovery: "+safeErrorMessage(dkerr))
		}
	}
	if len(discoveryNotes) == 0 {
		sink.system("Post-update rediscovery completed.")
		s.finishStep(ctx, operationID, StepDiscovery, "SUCCESS", pgtype.Int4{}, "Post-update rediscovery completed.", "")
	} else {
		note := strings.Join(discoveryNotes, " ")
		sink.system("Post-update rediscovery completed with warnings: " + note)
		s.finishStep(ctx, operationID, StepDiscovery, "FAILED", pgtype.Int4{}, "", note)
	}

	s.settlePlanAndAudit(ctx, op, planID, summary)
}

// verifyPackages queries the VM directly for each selected package's
// actual installed version (never assumed from exit code), records one
// update_operation_results row per package, and returns the tallies.
func (s *UpdateExecutionService) verifyPackages(ctx context.Context, client *ssh.Client, operationID uuid.UUID, pmType PackageManagerType, items []generated.UpdatePlanItem) (verified, failed, unknown int) {
	names := make([]string, 0, len(items))
	for _, it := range items {
		names = append(names, it.PackageName)
		_ = s.store.CreateOperationResult(ctx, generated.CreateOperationResultParams{
			OperationID: operationID, PackageName: it.PackageName, BeforeVersion: it.CurrentVersion, TargetVersion: it.TargetVersion,
		})
	}

	// Verify() (unlike Run()) has no earlier ValidatePackageNamesForExecution
	// call on this code path, and these names were read straight back out of
	// update_plan_items -- ultimately sourced from a VM's own dpkg-query/
	// rpm -qa discovery output (package_parse.go only trims whitespace, it
	// doesn't restrict the charset). A compromised or malicious VM could
	// therefore report a package name containing shell metacharacters; skip
	// the live re-query rather than concatenate an unvalidated name into the
	// SSH command below. Every item then falls through to the existing
	// !found branch and is reported UNKNOWN, exactly as if the SSH query
	// itself had failed.
	var installed map[string]string
	if err := ValidatePackageNamesForExecution(names); err == nil {
		switch pmType {
		case PMTypeAPT:
			res, err := s.executor.Execute(ctx, client, dpkgVersionQueryCmd+strings.Join(names, " "), s.sshCommandTimeout)
			if err == nil {
				installed = versionMapFromDpkg(res.Stdout)
			}
		case PMTypeDNF, PMTypeYUM:
			res, err := s.executor.Execute(ctx, client, rpmVersionQueryCmd+strings.Join(names, " "), s.sshCommandTimeout)
			if err == nil {
				installed = versionMapFromRPM(res.Stdout)
			}
		}
	}

	for _, it := range items {
		after, found := installed[it.PackageName]
		status := "UNKNOWN"
		switch {
		case !found:
			status = "UNKNOWN"
		case after == it.TargetVersion:
			status = "VERIFIED"
		case after == it.CurrentVersion:
			status = "FAILED"
		default:
			status = "UNKNOWN"
		}
		switch status {
		case "VERIFIED":
			verified++
		case "FAILED":
			failed++
		default:
			unknown++
		}
		_, _ = s.store.SetOperationResultStatus(ctx, generated.SetOperationResultStatusParams{
			OperationID: operationID, PackageName: it.PackageName, AfterVersion: pgutil.Text(after), Status: status,
		})
	}
	return verified, failed, unknown
}

func versionMapFromDpkg(output string) map[string]string {
	m := map[string]string{}
	for _, p := range ParseDpkgQuery(output) {
		m[p.Name] = p.Version
	}
	return m
}

func versionMapFromRPM(output string) map[string]string {
	m := map[string]string{}
	for _, p := range ParseRPMQA(output) {
		m[p.Name] = p.Version
	}
	return m
}

func anyDockerRelatedPackage(names []string) bool {
	for _, n := range names {
		if strings.Contains(strings.ToLower(n), "docker") || strings.Contains(strings.ToLower(n), "containerd") {
			return true
		}
	}
	return false
}

// fail is the shared terminal-failure path for early exits (before the
// UPDATE step ever ran), leaving both the operation and its plan in a
// clean, non-fabricated FAILED state.
func (s *UpdateExecutionService) fail(ctx context.Context, op generated.Operation, planID uuid.UUID, message string) {
	updated, err := s.transition(ctx, op, OpFailed, pgtype.Int4{}, message)
	if err != nil {
		return
	}
	s.settlePlanAndAudit(ctx, updated, planID, message)
}

// settlePlanAndAudit drives update_plans.status from the operation's now-
// terminal status and writes the matching audit event -- the single place
// every Run() exit path converges on, so the plan/audit outcome always
// mirrors the operation's real, evidence-based final status.
func (s *UpdateExecutionService) settlePlanAndAudit(ctx context.Context, op generated.Operation, planID uuid.UUID, summary string) {
	status := OperationStatus(op.Status)
	_, _ = s.store.SetUpdatePlanStatus(ctx, generated.SetUpdatePlanStatusParams{ID: planID, Status: planStatusForOperation(status)})

	action := AuditUpdateExecutionFailed
	switch status {
	case OpSuccess:
		action = AuditUpdateExecutionCompleted
	case OpPartial:
		action = AuditUpdateExecutionPartial
	}
	meta := map[string]any{"update_plan_id": planID, "operation_id": op.ID, "status": string(status), "summary": summary}
	_ = s.audit.Log(ctx, AuditEvent{UserID: uuidPtr(op.RequestedBy), Action: action, ResourceType: "VM", ResourceID: uuidPtr(op.ResourceID), Metadata: meta})
	_ = s.audit.Log(ctx, AuditEvent{UserID: uuidPtr(op.RequestedBy), Action: AuditUpdateVerificationComplete, ResourceType: "VM", ResourceID: uuidPtr(op.ResourceID), Metadata: meta})
}

// Cancel is only permitted while the operation hasn't begun touching
// package state yet (spec: "cancellation is unavailable while package
// changes are in progress" -- once RUNNING, no unsafe process killing is
// ever attempted here).
func (s *UpdateExecutionService) Cancel(ctx context.Context, operationID uuid.UUID) (generated.Operation, error) {
	op, err := s.store.GetOperationByID(ctx, operationID)
	if err != nil {
		return generated.Operation{}, ErrUpdateOperationNotFound
	}
	if OperationStatus(op.Status) != OpPending && OperationStatus(op.Status) != OpConnecting {
		return op, ErrUpdateCancelUnavailable
	}
	updated, err := s.transition(ctx, op, OpCancelled, pgtype.Int4{}, "Cancelled by admin before execution began.")
	if err != nil {
		return op, err
	}
	if updated.UpdatePlanID.Valid {
		_, _ = s.store.SetUpdatePlanStatus(ctx, generated.SetUpdatePlanStatusParams{ID: pgutil.UUID(updated.UpdatePlanID), Status: "READY"})
	}
	return updated, nil
}

// Verify is the admin-triggered, read-only re-check (POST
// /api/update-operations/:id/verify): re-queries actual installed
// versions and refreshes update_operation_results, but never re-executes
// the update command and never changes operations.status -- only a new
// plan/operation can ever change real VM state again.
func (s *UpdateExecutionService) Verify(ctx context.Context, operationID, userID uuid.UUID) ([]generated.UpdateOperationResult, error) {
	op, err := s.store.GetOperationByID(ctx, operationID)
	if err != nil {
		return nil, ErrUpdateOperationNotFound
	}
	if !op.UpdatePlanID.Valid {
		return nil, ErrUpdateOperationNotFound
	}
	planID := pgutil.UUID(op.UpdatePlanID)
	items, err := s.store.ListUpdatePlanItemsByPlan(ctx, planID)
	if err != nil {
		return nil, err
	}
	vm, err := s.store.GetVMByResourceID(ctx, pgutil.UUID(op.ResourceID))
	if err != nil {
		return nil, fmt.Errorf("load vm: %w", err)
	}
	client, err := s.ssh.Connect(ctx, vm.ResourceID)
	_ = RecordConnectionOutcome(ctx, s.store, vm.ResourceID, vm.ID, err)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	pmType := PackageManagerType(pgutil.TextOrEmpty(vm.PackageManager))
	s.verifyPackages(ctx, client, operationID, pmType, items)

	_ = s.audit.Log(ctx, AuditEvent{
		UserID: &userID, Action: AuditUpdateVerificationComplete, ResourceType: "VM", ResourceID: &vm.ResourceID,
		Metadata: map[string]any{"update_plan_id": planID, "operation_id": operationID, "manual": true},
	})
	return s.store.ListOperationResults(ctx, operationID)
}

func uuidPtr(id pgtype.UUID) *uuid.UUID {
	if !id.Valid {
		return nil
	}
	u := pgutil.UUID(id)
	return &u
}

func execCodeOrEmpty(execErr error, res CommandResult) pgtype.Int4 {
	if execErr != nil {
		return pgtype.Int4{}
	}
	return pgutil.Int4(int32(res.ExitCode))
}

func summarizeFailedChecks(report PrecheckReport) string {
	var failed []string
	for _, item := range report.Items {
		if item.Status == PrecheckFail {
			failed = append(failed, item.Name)
		}
	}
	if len(failed) == 0 {
		return "Pre-execution checks failed."
	}
	return "Pre-execution checks failed: " + strings.Join(failed, ", ")
}

// RecoverInterruptedOperations marks any operation left in a non-terminal
// state by an unclean prior shutdown as INTERRUPTED, and its linked plan
// FAILED -- called once at startup, before the HTTP server or worker pool
// starts accepting new work. Never automatically resumes anything (spec:
// "require Admin review").
func (s *UpdateExecutionService) RecoverInterruptedOperations(ctx context.Context) (int, error) {
	ops, err := s.store.ListNonTerminalOperations(ctx)
	if err != nil {
		return 0, fmt.Errorf("list non-terminal operations: %w", err)
	}
	const msg = "Backend stopped while this update was running. The final VM state must be verified manually."
	for _, op := range ops {
		updated, err := s.store.UpdateOperationStatus(ctx, generated.UpdateOperationStatusParams{
			ID: op.ID, Status: string(OpInterrupted), ExitCode: op.ExitCode, Summary: pgutil.Text(msg),
		})
		if err != nil {
			continue
		}
		if updated.UpdatePlanID.Valid {
			_, _ = s.store.SetUpdatePlanStatus(ctx, generated.SetUpdatePlanStatusParams{ID: pgutil.UUID(updated.UpdatePlanID), Status: "FAILED"})
		}
	}
	return len(ops), nil
}
