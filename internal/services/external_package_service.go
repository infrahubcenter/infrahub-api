package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// externalPackageArchitecture is a placeholder distinct from OS packages'
// own "unknown" fallback (nonEmptyOr in package_service.go) so the two
// can never collide under packages' (vm_id, name, architecture) unique
// constraint -- an OS package with an undetected architecture and an
// external package of the same name would otherwise fight over one row.
const externalPackageArchitecture = "n/a"

// ExternalPackageScanResult summarizes one Scan call -- mirrors
// PackageScanResult's philosophy (a failed outcome is represented here,
// not as a Go error, so the handler always renders something).
type ExternalPackageScanResult struct {
	Status       string // SUCCESS | FAILED
	PackageCount int
	ErrorSummary string
}

type externalEcosystem struct {
	packageManager string
	// command is fixed and backend-authored, never built from user
	// input, mirroring discovery.go's read-only-commands convention
	// exactly. Redirects stderr to /dev/null and, for pip, falls back
	// from pip3 to pip -- a nonzero exit (tool not installed) is a
	// normal, expected "nothing to report" outcome, not a scan failure.
	command string
	parse   func(string) []InstalledPackage
}

var externalEcosystems = []externalEcosystem{
	{packageManager: "PIP", command: "pip3 list --format=freeze 2>/dev/null || pip list --format=freeze 2>/dev/null", parse: ParsePipFreeze},
	{packageManager: "NPM", command: "npm list -g --depth=0 --json 2>/dev/null", parse: ParseNpmListJSON},
	{packageManager: "GEM", command: "gem list --local 2>/dev/null", parse: ParseGemList},
	{packageManager: "SNAP", command: "snap list 2>/dev/null", parse: ParseSnapList},
}

// ExternalPackageScanner discovers software installed outside the VM's
// OS package manager (pip/npm/gem/snap) -- list-only, by user decision:
// there is no generic "check the vendor's official site for an update"
// mechanism, so unlike PackageService this never checks for or reports
// available updates.
type ExternalPackageScanner struct {
	store          *repository.Store
	ssh            *SSHService
	executor       *RemoteExecutor
	commandTimeout time.Duration
}

// NewExternalPackageScanner creates an ExternalPackageScanner.
func NewExternalPackageScanner(store *repository.Store, ssh *SSHService, executor *RemoteExecutor, commandTimeout time.Duration) *ExternalPackageScanner {
	return &ExternalPackageScanner{store: store, ssh: ssh, executor: executor, commandTimeout: commandTimeout}
}

// Scan connects once, probes each known ecosystem in turn, and syncs
// whatever it finds via the same UpsertPackage upsert-on-conflict
// PackageService.Scan already uses -- then soft-deletes any previously
// seen external package not re-reported this run, scoped to just these
// ecosystems (MarkExternalPackagesRemovedSince) so OS packages are never
// touched.
func (s *ExternalPackageScanner) Scan(ctx context.Context, resourceID uuid.UUID) (ExternalPackageScanResult, error) {
	vm, err := s.store.GetVMByResourceID(ctx, resourceID)
	if err != nil {
		return ExternalPackageScanResult{}, fmt.Errorf("load vm: %w", err)
	}

	client, connErr := s.ssh.Connect(ctx, resourceID)
	if outcomeErr := RecordConnectionOutcome(ctx, s.store, resourceID, vm.ID, connErr); outcomeErr != nil {
		return ExternalPackageScanResult{}, fmt.Errorf("record connection outcome: %w", outcomeErr)
	}
	if connErr != nil {
		sshErr := classifyConnectError(connErr)
		return ExternalPackageScanResult{Status: "FAILED", ErrorSummary: "Connection failed: " + sshErr.Message}, nil
	}
	defer client.Close()

	scanStart := time.Now()
	count := 0
	for _, eco := range externalEcosystems {
		result, execErr := s.executor.Execute(ctx, client, eco.command, s.commandTimeout)
		if execErr != nil || result.ExitCode != 0 {
			continue
		}
		for _, pkg := range eco.parse(result.Stdout) {
			if _, err := s.store.UpsertPackage(ctx, generated.UpsertPackageParams{
				VmID: vm.ID, Name: pkg.Name, InstalledVersion: pkg.Version,
				PackageManager: eco.packageManager, Architecture: externalPackageArchitecture,
			}); err != nil {
				return ExternalPackageScanResult{}, fmt.Errorf("upsert external package %s: %w", pkg.Name, err)
			}
			count++
		}
	}

	if err := s.store.MarkExternalPackagesRemovedSince(ctx, generated.MarkExternalPackagesRemovedSinceParams{
		VmID: vm.ID, LastDiscoveredAt: pgutil.Timestamptz(scanStart),
	}); err != nil {
		return ExternalPackageScanResult{}, fmt.Errorf("mark removed external packages: %w", err)
	}

	return ExternalPackageScanResult{Status: "SUCCESS", PackageCount: count}, nil
}
