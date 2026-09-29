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

// Errors CreatePlan/ValidatePlan/ApprovePlan/CancelPlan return. Handlers
// map these to specific HTTP statuses rather than a generic 500 -- every
// one of them represents a real, expected validation outcome, not a bug.
var (
	ErrUpdatePlanNoItems           = errors.New("at least one package must be selected")
	ErrUpdatePlanVMInactive        = errors.New("vm is not active")
	ErrUpdatePlanDuplicateItem     = errors.New("duplicate package in update plan")
	ErrUpdatePlanPackageNotFound   = errors.New("package not found for this vm")
	ErrUpdatePlanUpdateUnavailable = errors.New("this package no longer has an available update")
	ErrUpdatePlanNotDraft          = errors.New("update plan must be in DRAFT status for this action")
	ErrUpdatePlanTerminal          = errors.New("update plan is already in a terminal status")
	ErrUpdatePlanChecksFailed      = errors.New("update plan failed one or more required prechecks")
	ErrUpdatePlanExecuting         = errors.New("update plan execution is in progress and cannot be modified")
)

// PrecheckStatus mirrors the spec's ✓/⚠/✗ vocabulary (spec #34/#38).
type PrecheckStatus string

const (
	PrecheckPass    PrecheckStatus = "PASS"
	PrecheckFail    PrecheckStatus = "FAIL" // blocks the plan from becoming READY
	PrecheckWarn    PrecheckStatus = "WARN" // shown prominently, never blocks (spec #36/#37)
	PrecheckInfo    PrecheckStatus = "INFO" // display-only, no pass/fail semantics (spec #35's "no arbitrary minimum")
	PrecheckUnknown PrecheckStatus = "UNKNOWN"
)

// PrecheckItem is one row of the pre-update checklist (spec #34/#41).
type PrecheckItem struct {
	Name    string
	Status  PrecheckStatus
	Message string
}

// PrecheckReport is the full checklist plus whether it blocks readiness.
type PrecheckReport struct {
	Items     []PrecheckItem
	AllPassed bool // true iff no item has Status == PrecheckFail
}

func (r *PrecheckReport) add(name string, status PrecheckStatus, message string) {
	r.Items = append(r.Items, PrecheckItem{Name: name, Status: status, Message: message})
	if status == PrecheckFail {
		r.AllPassed = false
	}
}

// ValidateResult is ValidatePlan's full outcome: the precheck report plus
// whether the plan's snapshotted items have drifted from current package
// data (spec #28's STALE detection).
type ValidateResult struct {
	Report     PrecheckReport
	Stale      bool
	StaleItems []string // package names whose available update changed or disappeared
}

// UpdatePlanService implements the admin update-planning workflow (Step 9
// spec #51). Every method here only ever reads state or writes to
// update_plans/update_plan_items -- nothing in this file ever connects
// to a VM to install, upgrade, remove, or reboot anything. The one real
// SSH activity (a plain connectivity test, mirroring
// POST /api/vms/:id/connection-test from Step 5) happens inside
// ValidatePlan's VM-reachable precheck, and even that never runs a
// command -- it only opens and immediately closes a connection.
type UpdatePlanService struct {
	store              *repository.Store
	ssh                *SSHService
	metadataStaleAfter time.Duration
}

// NewUpdatePlanService creates an UpdatePlanService. metadataStaleAfter
// is UPDATE_METADATA_STALE_AFTER.
func NewUpdatePlanService(store *repository.Store, ssh *SSHService, metadataStaleAfter time.Duration) *UpdatePlanService {
	return &UpdatePlanService{store: store, ssh: ssh, metadataStaleAfter: metadataStaleAfter}
}

// PlanItemSelection is one admin-selected package (spec #25's request
// shape). TargetVersion is accepted only so a stale client-side
// selection can be detected against the database's current value at
// validation time -- CreatePlan itself always resolves and stores the
// database's own available_version, never this field (spec #25: "Do not
// trust target version from frontend. Prefer resolving target version
// from the database.").
type PlanItemSelection struct {
	PackageID     uuid.UUID
	TargetVersion string
}

// CreatePlan builds a DRAFT update plan for resourceID from the admin's
// selected packages. Every item is validated server-side: the package
// must belong to this VM and currently have an available update (spec
// #27 #1-8, applied at creation time as well as at validation time).
func (s *UpdatePlanService) CreatePlan(ctx context.Context, resourceID, createdBy uuid.UUID, selections []PlanItemSelection) (generated.UpdatePlan, []generated.UpdatePlanItem, error) {
	if len(selections) == 0 {
		return generated.UpdatePlan{}, nil, ErrUpdatePlanNoItems
	}

	resource, err := s.store.GetVMResourceByID(ctx, resourceID)
	if err != nil {
		return generated.UpdatePlan{}, nil, fmt.Errorf("load resource: %w", err)
	}
	if resource.Status == "DISABLED" {
		return generated.UpdatePlan{}, nil, ErrUpdatePlanVMInactive
	}
	vm, err := s.store.GetVMByResourceID(ctx, resourceID)
	if err != nil {
		return generated.UpdatePlan{}, nil, fmt.Errorf("load vm: %w", err)
	}

	seen := make(map[uuid.UUID]bool, len(selections))
	for _, sel := range selections {
		if seen[sel.PackageID] {
			return generated.UpdatePlan{}, nil, ErrUpdatePlanDuplicateItem
		}
		seen[sel.PackageID] = true
	}

	plan, err := s.store.CreateUpdatePlan(ctx, generated.CreateUpdatePlanParams{
		VmID: vm.ID, CreatedBy: pgutil.NullUUID(&createdBy),
	})
	if err != nil {
		return generated.UpdatePlan{}, nil, fmt.Errorf("create update plan: %w", err)
	}

	pmType := PackageManagerType(pgutil.TextOrEmpty(vm.PackageManager))
	items := make([]generated.UpdatePlanItem, 0, len(selections))
	for _, sel := range selections {
		pkg, err := s.store.GetPackageWithStatusByID(ctx, generated.GetPackageWithStatusByIDParams{ID: sel.PackageID, VmID: vm.ID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return generated.UpdatePlan{}, nil, ErrUpdatePlanPackageNotFound
			}
			return generated.UpdatePlan{}, nil, fmt.Errorf("load package %s: %w", sel.PackageID, err)
		}
		if !pkg.UpdateID.Valid {
			return generated.UpdatePlan{}, nil, ErrUpdatePlanUpdateUnavailable
		}

		updateType := "PACKAGE"
		if IsKernelPackageName(pkg.Name, pmType) {
			updateType = "KERNEL"
		}
		item, err := s.store.InsertUpdatePlanItem(ctx, generated.InsertUpdatePlanItemParams{
			UpdatePlanID: plan.ID, PackageID: pkg.ID, PackageName: pkg.Name,
			CurrentVersion: pkg.InstalledVersion,
			// Always the database's own current available_version --
			// sel.TargetVersion is never written anywhere.
			TargetVersion:  pgutil.TextOrEmpty(pkg.AvailableVersion),
			UpdateType:     updateType,
			SecurityUpdate: pkg.IsSecurityUpdate.Bool,
			Severity:       nonEmptyOr(pgutil.TextOrEmpty(pkg.UpdateSeverity), "UNKNOWN"),
		})
		if err != nil {
			return generated.UpdatePlan{}, nil, fmt.Errorf("insert plan item for %s: %w", pkg.Name, err)
		}
		items = append(items, item)
	}

	return plan, items, nil
}

// GetPlanDetail loads a plan plus its items and VM/creator identity for
// the plan-detail endpoint.
func (s *UpdatePlanService) GetPlanDetail(ctx context.Context, planID uuid.UUID) (generated.GetUpdatePlanDetailRow, []generated.UpdatePlanItem, error) {
	detail, err := s.store.GetUpdatePlanDetail(ctx, planID)
	if err != nil {
		return generated.GetUpdatePlanDetailRow{}, nil, err
	}
	items, err := s.store.ListUpdatePlanItemsByPlan(ctx, planID)
	if err != nil {
		return generated.GetUpdatePlanDetailRow{}, nil, err
	}
	return detail, items, nil
}

// ValidatePlan runs the full read-only precheck (spec #27/#34-38) for
// planID and reports whether its snapshotted items have drifted (spec
// #28). Never mutates plan.status -- ApprovePlan is the action that
// actually commits a transition, using this same report as its
// precondition. Equivalent to ValidatePlanForExecution with no excluded
// operation -- see that method's doc comment for why one is sometimes
// needed.
func (s *UpdatePlanService) ValidatePlan(ctx context.Context, planID uuid.UUID) (ValidateResult, error) {
	return s.validatePlan(ctx, planID, uuid.Nil)
}

// ValidatePlanForExecution is ValidatePlan, except the concurrency-lock
// check excludes excludeOperationID from what counts as "a conflicting
// operation." Used exclusively by the execution engine's own PRECHECK
// step (update_execution_run.go): by the time that step runs, the
// operation it belongs to already exists and is itself non-terminal
// (exclusivity was already guaranteed atomically at claim time by
// GetActiveOperationForResourceLocked) -- without this exclusion, every
// execution would immediately fail its own precheck by "conflicting"
// with itself.
func (s *UpdatePlanService) ValidatePlanForExecution(ctx context.Context, planID, excludeOperationID uuid.UUID) (ValidateResult, error) {
	return s.validatePlan(ctx, planID, excludeOperationID)
}

func (s *UpdatePlanService) validatePlan(ctx context.Context, planID, excludeOperationID uuid.UUID) (ValidateResult, error) {
	plan, err := s.store.GetUpdatePlanByID(ctx, planID)
	if err != nil {
		return ValidateResult{}, err
	}
	vm, err := s.store.GetVMByID(ctx, plan.VmID)
	if err != nil {
		return ValidateResult{}, fmt.Errorf("load vm: %w", err)
	}
	items, err := s.store.ListUpdatePlanItemsByPlan(ctx, planID)
	if err != nil {
		return ValidateResult{}, fmt.Errorf("list plan items: %w", err)
	}

	report := PrecheckReport{AllPassed: true}

	// --- VM-level checks (spec #27 #1-3, also exposed standalone via
	// POST /api/vms/:id/updates/precheck) ---
	s.vmLevelPrechecks(ctx, &report, vm)

	// --- Concurrency lock (spec #27 #still-relevant, #40) ---
	var excludeParam pgtype.UUID
	if excludeOperationID != uuid.Nil {
		excludeParam = pgutil.NullUUID(&excludeOperationID)
	}
	if op, err := s.store.GetRunningUpdateOperationByResource(ctx, generated.GetRunningUpdateOperationByResourceParams{
		ResourceID: pgutil.NullUUID(&vm.ResourceID), ExcludeOperationID: excludeParam,
	}); err == nil {
		report.add("no_conflicting_operation", PrecheckFail, fmt.Sprintf("An update operation is currently running (started %s).", op.StartedAt.Time.Format(time.RFC3339)))
	} else if errors.Is(err, pgx.ErrNoRows) {
		report.add("no_conflicting_operation", PrecheckPass, "No update operation currently running.")
	} else {
		report.add("no_conflicting_operation", PrecheckUnknown, "Could not determine whether an update operation is running.")
	}

	// Reboot exclusivity (Step 11): a VM currently rebooting must never
	// also start an update -- read-only preview here; the authoritative
	// check is the transactional claim in UpdateExecutionService.RequestExecution.
	if _, err := s.store.GetActiveRebootForResourceLocked(ctx, generated.GetActiveRebootForResourceLockedParams{VmID: vm.ID}); err == nil {
		report.add("no_reboot_running", PrecheckFail, "This VM is currently rebooting.")
	} else if !errors.Is(err, pgx.ErrNoRows) {
		report.add("no_reboot_running", PrecheckUnknown, "Could not determine whether this VM is rebooting.")
	}

	// --- Item-level checks: still available, no duplicates, still
	// matches current package data (spec #27 #5-7, #28) ---
	stale := false
	var staleNames []string
	seen := make(map[uuid.UUID]bool, len(items))
	itemsOK := true
	for _, item := range items {
		if seen[item.PackageID] {
			report.add("no_duplicate_items", PrecheckFail, fmt.Sprintf("%s is selected more than once.", item.PackageName))
			itemsOK = false
			continue
		}
		seen[item.PackageID] = true

		pkg, err := s.store.GetPackageWithStatusByID(ctx, generated.GetPackageWithStatusByIDParams{ID: item.PackageID, VmID: vm.ID})
		if err != nil || !pkg.UpdateID.Valid {
			report.add("updates_still_available", PrecheckFail, fmt.Sprintf("%s no longer has an available update.", item.PackageName))
			itemsOK = false
			stale = true
			staleNames = append(staleNames, item.PackageName)
			continue
		}
		if pgutil.TextOrEmpty(pkg.AvailableVersion) != item.TargetVersion {
			stale = true
			staleNames = append(staleNames, item.PackageName)
		}
	}
	if len(items) == 0 {
		report.add("has_selected_items", PrecheckFail, "This plan has no selected packages.")
	} else if itemsOK && !stale {
		report.add("updates_still_available", PrecheckPass, fmt.Sprintf("All %d selected update(s) are still available.", len(items)))
	}
	if stale {
		report.add("plan_current", PrecheckWarn, "One or more selected packages changed since this plan was created; revalidate before approval.")
	}

	// --- Informational, non-blocking checks (spec #36/#37) ---
	s.informationalPrechecks(ctx, &report, vm)

	return ValidateResult{Report: report, Stale: stale, StaleItems: staleNames}, nil
}

// RunVMPrecheck runs only the VM-level subset of ValidatePlan's checks
// (spec #47's standalone POST /api/vms/:id/updates/precheck) -- useful
// before any plan exists yet.
func (s *UpdatePlanService) RunVMPrecheck(ctx context.Context, resourceID uuid.UUID) (PrecheckReport, error) {
	vm, err := s.store.GetVMByResourceID(ctx, resourceID)
	if err != nil {
		return PrecheckReport{}, fmt.Errorf("load vm: %w", err)
	}
	report := PrecheckReport{AllPassed: true}
	s.vmLevelPrechecks(ctx, &report, vm)
	s.informationalPrechecks(ctx, &report, vm)
	return report, nil
}

func (s *UpdatePlanService) vmLevelPrechecks(ctx context.Context, report *PrecheckReport, vm generated.Vm) {
	if hasCred, err := s.store.HasSSHCredential(ctx, vm.ResourceID); err != nil || !hasCred {
		report.add("ssh_configured", PrecheckFail, "No SSH credential is configured for this VM.")
	} else {
		report.add("ssh_configured", PrecheckPass, "SSH credential is configured.")

		// VM reachable: a plain connectivity test, mirroring Step 5's
		// POST /api/vms/:id/connection-test -- never runs a command.
		client, connErr := s.ssh.Connect(ctx, vm.ResourceID)
		if outcomeErr := RecordConnectionOutcome(ctx, s.store, vm.ResourceID, vm.ID, connErr); outcomeErr != nil {
			report.add("vm_reachable", PrecheckUnknown, "Could not record connection outcome.")
		} else if connErr != nil {
			report.add("vm_reachable", PrecheckFail, "VM is not reachable: "+classifyConnectError(connErr).Message)
		} else {
			client.Close()
			report.add("vm_reachable", PrecheckPass, "VM is reachable over SSH.")
		}
	}

	pmType := PackageManagerType(pgutil.TextOrEmpty(vm.PackageManager))
	if pmType == PMTypeAPT || pmType == PMTypeDNF || pmType == PMTypeYUM {
		report.add("package_manager_detected", PrecheckPass, fmt.Sprintf("Detected: %s", pmType))
	} else {
		report.add("package_manager_detected", PrecheckFail, "No supported package manager has been detected for this VM.")
	}
}

func (s *UpdatePlanService) informationalPrechecks(ctx context.Context, report *PrecheckReport, vm generated.Vm) {
	// Package metadata freshness (spec #37) -- WARN, never blocks.
	if run, err := s.store.GetLatestPackageDiscoveryRun(ctx, vm.ID); err == nil && run.CompletedAt.Valid {
		age := time.Since(run.CompletedAt.Time)
		if age > s.metadataStaleAfter {
			report.add("package_metadata_fresh", PrecheckWarn, fmt.Sprintf("Package information may be stale (last scan %s ago). Rescan before execution.", age.Round(time.Minute)))
		} else {
			report.add("package_metadata_fresh", PrecheckPass, fmt.Sprintf("Package information is current (last scan %s ago).", age.Round(time.Minute)))
		}
	} else {
		report.add("package_metadata_fresh", PrecheckWarn, "No package scan has ever run for this VM.")
	}

	// Disk space (spec #35) -- informational only, no configured
	// minimum, never blocks.
	if filesystems, err := s.store.ListLatestVMFilesystems(ctx, vm.ID); err == nil {
		for _, fs := range filesystems {
			if fs.MountPoint != "/" {
				continue
			}
			if fs.UsagePercent.Valid {
				report.add("disk_space", PrecheckInfo, fmt.Sprintf("Root filesystem: %.0f%% used, %s available.", fs.UsagePercent.Float64, formatBytesGB(fs.AvailableBytes)))
			} else {
				report.add("disk_space", PrecheckUnknown, "Root filesystem usage is unavailable.")
			}
			break
		}
	}

	// VM monitoring health (spec #36) -- WARN, never blocks.
	snapshot, err := s.store.GetLatestMonitoringSnapshot(ctx, vm.ResourceID)
	hasSnapshot := err == nil
	storedHealth := HealthUnknown
	if hasSnapshot {
		storedHealth = HealthStatus(pgutil.TextOrEmpty(snapshot.Status))
	}
	health := DeriveDisplayHealth(hasSnapshot, vm.ConnectionStatus == "CONNECTED", storedHealth)
	switch health {
	case HealthCritical, HealthOffline, HealthUnknown:
		report.add("vm_health", PrecheckWarn, fmt.Sprintf("VM health is %s. Review VM health before applying updates.", health))
	default:
		report.add("vm_health", PrecheckPass, fmt.Sprintf("VM health is %s.", health))
	}

	// Reboot state (spec #11/#12) -- informational display only.
	switch pgutil.TextOrEmpty(vm.RebootStatus) {
	case "REQUIRED":
		msg := "Reboot is already required."
		if reason := pgutil.TextOrEmpty(vm.RebootReason); reason != "" {
			msg = reason
		}
		report.add("reboot_state", PrecheckInfo, msg)
	case "NOT_REQUIRED":
		report.add("reboot_state", PrecheckInfo, "No reboot currently required.")
	default:
		report.add("reboot_state", PrecheckUnknown, "Reboot state has not been detected yet.")
	}
}

// ApprovePlan re-runs ValidatePlan as a precondition and, only if every
// blocking check passes, transitions the plan DRAFT -> READY (spec #23/
// #38/#42: "'Approve Plan' only moves DRAFT -> READY. It must NOT execute
// the command."). Never opens a second SSH connection beyond what
// ValidatePlan itself performs.
func (s *UpdatePlanService) ApprovePlan(ctx context.Context, planID uuid.UUID) (generated.UpdatePlan, ValidateResult, error) {
	plan, err := s.store.GetUpdatePlanByID(ctx, planID)
	if err != nil {
		return generated.UpdatePlan{}, ValidateResult{}, err
	}
	if plan.Status != "DRAFT" {
		return plan, ValidateResult{}, ErrUpdatePlanNotDraft
	}

	result, err := s.ValidatePlan(ctx, planID)
	if err != nil {
		return plan, ValidateResult{}, err
	}
	if !result.Report.AllPassed {
		return plan, result, ErrUpdatePlanChecksFailed
	}

	updated, err := s.store.SetUpdatePlanStatus(ctx, generated.SetUpdatePlanStatusParams{ID: planID, Status: "READY"})
	if err != nil {
		return plan, result, fmt.Errorf("set plan status: %w", err)
	}
	return updated, result, nil
}

// CancelPlan moves any non-terminal plan to CANCELLED.
func (s *UpdatePlanService) CancelPlan(ctx context.Context, planID uuid.UUID) (generated.UpdatePlan, error) {
	plan, err := s.store.GetUpdatePlanByID(ctx, planID)
	if err != nil {
		return generated.UpdatePlan{}, err
	}
	switch plan.Status {
	case "COMPLETED", "FAILED", "PARTIAL", "CANCELLED":
		return plan, ErrUpdatePlanTerminal
	case "EXECUTING":
		// Once execution has begun the plan is locked -- the execution
		// engine, not an admin cancel action, is what drives its status
		// from here (spec: "once execution begins, no modification of
		// selected packages/target versions/command").
		return plan, ErrUpdatePlanExecuting
	}
	return s.store.SetUpdatePlanStatus(ctx, generated.SetUpdatePlanStatusParams{ID: planID, Status: "CANCELLED"})
}

// formatBytesGB renders a possibly-NULL byte count as a human GB string
// for one precheck message line -- the handler layer's own DTOs still
// carry the raw numeric field for the API response; this is only for the
// message text.
func formatBytesGB(v pgtype.Int8) string {
	if !v.Valid {
		return "unknown"
	}
	return fmt.Sprintf("%.1f GB", float64(v.Int64)/(1024*1024*1024))
}
