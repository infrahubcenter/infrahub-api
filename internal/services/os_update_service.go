package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// Fixed, backend-authored, read-only commands (Step 9 spec #4/#9/#11).
// None of these ever install, upgrade, remove, or reboot anything --
// do-release-upgrade's own "-c" flag is documented specifically as a
// check that performs no upgrade, and needs-restarting's "-r" flag is
// documented specifically as a query that changes nothing. cmdOSRelease
// and cmdKernel already exist in discovery.go (Step 5) -- reused here
// verbatim rather than redeclared, since they're the exact same commands
// for the exact same purpose ("read the current OS/kernel identity"),
// just re-run fresh instead of trusted from Step 5's last discovery.
const (
	cmdDoReleaseUpgradeCheckExists = "command -v do-release-upgrade"
	cmdDoReleaseUpgradeCheck       = "do-release-upgrade -c"
	cmdDebianRebootCheck           = `sh -c 'if [ -f /var/run/reboot-required ]; then echo REQUIRED; cat /var/run/reboot-required.pkgs 2>/dev/null; else echo NOT_REQUIRED; fi'`
	cmdNeedsRestartingExists       = "command -v needs-restarting"
	cmdNeedsRestarting             = "needs-restarting -r"
)

// OSUpdateResult summarizes one Scan call -- mirrors PackageScanResult/
// DockerScanResult's philosophy: a failed or partial outcome is
// represented here, not as a Go error, so the caller can always render
// *something* rather than a generic 500.
type OSUpdateResult struct {
	Status       string // SUCCESS | PARTIAL | FAILED
	OSStatus     string // UP_TO_DATE | UPDATE_AVAILABLE | UNKNOWN | BLOCKED
	RebootStatus string // NOT_REQUIRED | REQUIRED | UNKNOWN
	ErrorSummary string
}

// OSUpdateService detects OS release availability, kernel updates, and
// reboot requirement (Step 9 spec #50). Mirrors PackageService/
// DockerDiscoveryService's shape: connect once via SSHService (Step 5,
// unchanged), never a second SSH implementation; parsing lives entirely
// in os_update_parse.go. Deliberately re-detects OS/kernel state fresh on
// every scan rather than trusting Step 5's discovery snapshot or Step 7's
// package-manager detection being still current -- the same "detect
// independently" discipline Step 8 established for Docker daemon status.
type OSUpdateService struct {
	store          *repository.Store
	ssh            *SSHService
	executor       *RemoteExecutor
	commandTimeout time.Duration
}

// NewOSUpdateService creates an OSUpdateService.
func NewOSUpdateService(store *repository.Store, ssh *SSHService, executor *RemoteExecutor, commandTimeout time.Duration) *OSUpdateService {
	return &OSUpdateService{store: store, ssh: ssh, executor: executor, commandTimeout: commandTimeout}
}

// Scan runs one full OS/kernel/reboot detection cycle for resourceID.
// Never installs, upgrades, removes, or reboots anything -- this step's
// single hard mandate (spec's own repeated "THIS STEP MUST NOT EXECUTE
// ACTUAL OS OR PACKAGE UPDATES").
func (s *OSUpdateService) Scan(ctx context.Context, resourceID uuid.UUID) (OSUpdateResult, error) {
	vm, err := s.store.GetVMByResourceID(ctx, resourceID)
	if err != nil {
		return OSUpdateResult{}, fmt.Errorf("load vm: %w", err)
	}

	client, connErr := s.ssh.Connect(ctx, resourceID)
	if outcomeErr := RecordConnectionOutcome(ctx, s.store, resourceID, vm.ID, connErr); outcomeErr != nil {
		return OSUpdateResult{}, fmt.Errorf("record connection outcome: %w", outcomeErr)
	}
	if connErr != nil {
		sshErr := classifyConnectError(connErr)
		return OSUpdateResult{Status: "FAILED", ErrorSummary: "Connection failed: " + sshErr.Message}, nil
	}
	defer client.Close()

	pmType := PackageManagerType(pgutil.TextOrEmpty(vm.PackageManager))

	var errs []string

	osStatus, osErr := s.detectOSRelease(ctx, client, vm)
	if osErr != nil {
		errs = append(errs, "OS release detection: "+safeErrorMessage(osErr))
	}

	kernelRunning, kernelAvailable, kernelErr := s.detectKernel(ctx, client, vm.ID, pmType)
	if kernelErr != nil {
		errs = append(errs, "kernel detection: "+safeErrorMessage(kernelErr))
	}

	rebootStatus, rebootReason := "UNKNOWN", ""
	if kernelRunning != "" {
		rebootStatus, rebootReason = s.detectReboot(ctx, client, pmType, kernelRunning, kernelAvailable)
		if _, err := s.store.UpdateVMKernelStatus(ctx, generated.UpdateVMKernelStatusParams{
			ID: vm.ID, KernelVersion: pgutil.Text(kernelRunning), KernelAvailable: pgutil.Text(kernelAvailable),
			RebootStatus: pgutil.Text(rebootStatus), RebootReason: pgutil.Text(rebootReason),
		}); err != nil {
			return OSUpdateResult{}, fmt.Errorf("update vm kernel status: %w", err)
		}
		s.syncRebootRecommendation(ctx, vm.ResourceID, rebootStatus, rebootReason)
	} else {
		errs = append(errs, "reboot detection skipped: kernel version unknown")
	}

	status := "SUCCESS"
	errorSummary := ""
	if len(errs) > 0 {
		status = "PARTIAL"
		errorSummary = strings.Join(errs, "; ")
	}
	return OSUpdateResult{Status: status, OSStatus: osStatus, RebootStatus: rebootStatus, ErrorSummary: errorSummary}, nil
}

// rebootRecommendationSource is the source_type/source_id pair
// deduplicating one VM's live reboot-required condition to a single
// recommendation row (spec #82: "use vm_id + recommendation type +
// active state to deduplicate" -- source_id being the VM's own resource
// ID already guarantees at most one row per VM via the existing
// recommendations_source_unique_idx, exactly like every other Step 7
// source-tracked recommendation).
const rebootRecommendationSource = "VM_REBOOT_REQUIRED"

// syncRebootRecommendation creates/refreshes a REBOOT_REQUIRED
// recommendation when reboot is REQUIRED, and resolves it the moment a
// scan (whether Update Center's own, or Step 10/11's post-update/
// post-reboot rediscovery) observes NOT_REQUIRED -- never a duplicate,
// never fabricated: driven entirely by this scan's own real evidence.
func (s *OSUpdateService) syncRebootRecommendation(ctx context.Context, resourceID uuid.UUID, rebootStatus, rebootReason string) {
	if rebootStatus != "REQUIRED" {
		_ = s.store.ResolveRecommendationBySource(ctx, generated.ResolveRecommendationBySourceParams{
			SourceType: pgutil.Text(rebootRecommendationSource), SourceID: pgutil.NullUUID(&resourceID),
		})
		return
	}
	description := rebootReason
	if description == "" {
		description = "A reboot is required to complete a pending system change."
	}
	_, _ = s.store.UpsertRecommendationBySource(ctx, generated.UpsertRecommendationBySourceParams{
		ResourceID: resourceID, Type: "REBOOT_REQUIRED", Severity: "MEDIUM", Title: "Reboot required",
		Description: pgutil.Text(description), Metadata: []byte("{}"),
		SourceType: pgutil.Text(rebootRecommendationSource), SourceID: pgutil.NullUUID(&resourceID),
	})
}

// detectOSRelease reads /etc/os-release fresh, and for Ubuntu only, asks
// do-release-upgrade -c whether a new distribution release is available
// (spec #4/#5). Every other distribution's release-upgrade availability
// is reported as UNKNOWN -- there is no universal, safe, read-only
// mechanism to check this across Debian/RPM families without additional
// tooling that itself makes system changes just by being installed
// (spec #57's "do not fabricate release information").
func (s *OSUpdateService) detectOSRelease(ctx context.Context, client *ssh.Client, vm generated.Vm) (string, error) {
	res, err := s.executor.Execute(ctx, client, cmdOSRelease, s.commandTimeout)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("cat /etc/os-release exited with status %d", res.ExitCode)
	}
	info, ok := ParseOSReleaseFull(res.Stdout)
	if !ok {
		return "", fmt.Errorf("could not parse /etc/os-release")
	}

	currentVersion := info.Version
	if currentVersion == "" {
		currentVersion = pgutil.TextOrEmpty(vm.OsVersion)
	}
	if currentVersion == "" {
		return "", fmt.Errorf("no OS version available from /etc/os-release or prior discovery")
	}

	status := "UNKNOWN"
	updateType := ""
	availableVersion := ""

	if info.ID == "ubuntu" {
		if existsRes, err := s.executor.Execute(ctx, client, cmdDoReleaseUpgradeCheckExists, s.commandTimeout); err == nil && existsRes.ExitCode == 0 {
			if checkRes, err := s.executor.Execute(ctx, client, cmdDoReleaseUpgradeCheck, s.commandTimeout); err == nil {
				check := ParseDoReleaseUpgradeCheck(checkRes.Stdout)
				if check.Available {
					status, updateType, availableVersion = "UPDATE_AVAILABLE", "RELEASE", check.NewRelease
				} else {
					status, availableVersion = "UP_TO_DATE", currentVersion
				}
			}
		}
	}

	channel := ReleaseChannel(info.ID, info.Version)

	if _, err := s.store.UpsertOSUpdateStatus(ctx, generated.UpsertOSUpdateStatusParams{
		VmID: vm.ID, CurrentVersion: currentVersion, AvailableVersion: pgutil.Text(availableVersion),
		UpdateType: pgutil.Text(updateType), Status: status, ReleaseChannel: pgutil.Text(channel),
	}); err != nil {
		return "", fmt.Errorf("upsert os update status: %w", err)
	}
	return status, nil
}

// detectKernel runs exactly one new command (`uname -r`) and otherwise
// reuses Step 7's already-synced packages/package_updates data (spec #8:
// "Do NOT create duplicate package update records") to find the newest
// known kernel package version, installed or pending.
func (s *OSUpdateService) detectKernel(ctx context.Context, client *ssh.Client, vmRowID uuid.UUID, pmType PackageManagerType) (running, available string, err error) {
	res, execErr := s.executor.Execute(ctx, client, cmdKernel, s.commandTimeout)
	if execErr != nil {
		return "", "", execErr
	}
	if res.ExitCode != 0 {
		return "", "", fmt.Errorf("uname -r exited with status %d", res.ExitCode)
	}
	running = strings.TrimSpace(res.Stdout)
	if running == "" {
		return "", "", fmt.Errorf("uname -r returned empty output")
	}
	if pmType != PMTypeAPT && pmType != PMTypeDNF && pmType != PMTypeYUM {
		// No package-manager-specific kernel package-name convention to
		// match against -- running kernel is still real, reported data.
		return running, "", nil
	}

	installed, err := s.store.ListPackagesByVM(ctx, vmRowID)
	if err != nil {
		return running, "", fmt.Errorf("list installed packages: %w", err)
	}
	newestInstalled := ""
	for _, p := range installed {
		if v, ok := ExtractKernelVersion(p.Name, p.InstalledVersion, pmType); ok {
			if newestInstalled == "" || CompareKernelVersions(v, newestInstalled) {
				newestInstalled = v
			}
		}
	}

	newestPending := ""
	if updates, err := s.store.ListPackageUpdatesByVM(ctx, generated.ListPackageUpdatesByVMParams{VmID: vmRowID, Limit: 500}); err == nil {
		for _, u := range updates {
			if v, ok := ExtractKernelVersion(u.PackageName, u.AvailableVersion, pmType); ok {
				if newestPending == "" || CompareKernelVersions(v, newestPending) {
					newestPending = v
				}
			}
		}
	}

	available = newestPending
	if available == "" {
		available = newestInstalled
	}
	if available == running {
		// Nothing to report beyond "running" itself -- never fabricate a
		// difference that doesn't exist.
		available = ""
	}
	return running, available, nil
}

// detectReboot combines two independent kinds of evidence: a kernel
// version mismatch (the most specific signal -- spec #10's exact
// wording), and the distribution's own reboot-required indicator (spec
// #11's named paths for Debian/Ubuntu, needs-restarting -r for RPM).
// Returns UNKNOWN, never a guessed NOT_REQUIRED, when neither signal is
// available.
func (s *OSUpdateService) detectReboot(ctx context.Context, client *ssh.Client, pmType PackageManagerType, kernelRunning, kernelAvailable string) (status, reason string) {
	if kernelAvailable != "" && kernelAvailable != kernelRunning {
		status, reason = "REQUIRED", "Kernel update is installed but requires reboot to become active."
	}

	switch pmType {
	case PMTypeAPT:
		res, err := s.executor.Execute(ctx, client, cmdDebianRebootCheck, s.commandTimeout)
		if err != nil || res.ExitCode != 0 {
			break
		}
		check, ok := ParseDebianRebootCheck(res.Stdout)
		if !ok {
			break
		}
		if check.Required {
			status = "REQUIRED"
			switch {
			case len(check.Packages) > 0:
				reason = "Reboot required by package updates: " + strings.Join(check.Packages, ", ")
			case reason == "":
				reason = "Reboot required by package updates."
			}
		} else if status == "" {
			status = "NOT_REQUIRED"
		}
		return status, reason

	case PMTypeDNF, PMTypeYUM:
		existsRes, err := s.executor.Execute(ctx, client, cmdNeedsRestartingExists, s.commandTimeout)
		if err != nil || existsRes.ExitCode != 0 {
			break
		}
		checkRes, err := s.executor.Execute(ctx, client, cmdNeedsRestarting, s.commandTimeout)
		if err != nil {
			break
		}
		switch checkRes.ExitCode {
		case 0:
			if status == "" {
				status = "NOT_REQUIRED"
			}
		case 1:
			status = "REQUIRED"
			if reason == "" {
				reason = "Reboot required by package updates."
			}
		}
		return status, reason
	}

	if status == "" {
		status = "UNKNOWN"
	}
	return status, reason
}
