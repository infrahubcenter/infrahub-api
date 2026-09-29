package services

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// PackageScanResult summarizes one Scan/RefreshUpdates call -- mirrors
// DiscoveryResult/MonitoringResult's philosophy (Steps 5-6): a failed or
// partial outcome is represented here, not as a Go error, so the handler
// can always render *something* rather than a generic 500.
type PackageScanResult struct {
	Status         string // SUCCESS | PARTIAL | FAILED
	PackageManager PackageManagerType
	PackageCount   int
	UpdateCount    int
	ErrorSummary   string
}

// PackageService orchestrates package discovery and update checking.
// Mirrors VMDiscoveryService/VMMonitoringService's shape closely: connect
// once via SSHService (Step 5, unchanged), never a second SSH
// implementation; parsing lives in package_parse.go, never inline here.
type PackageService struct {
	store          *repository.Store
	ssh            *SSHService
	detector       *PackageManagerDetector
	factory        *PackageManagerFactory
	commandTimeout time.Duration
}

// NewPackageService creates a PackageService.
func NewPackageService(store *repository.Store, ssh *SSHService, detector *PackageManagerDetector, factory *PackageManagerFactory, commandTimeout time.Duration) *PackageService {
	return &PackageService{store: store, ssh: ssh, detector: detector, factory: factory, commandTimeout: commandTimeout}
}

// Scan runs a full package discovery cycle for resourceID: detect the
// package manager, list every installed package (syncing packages --
// inserting new ones, updating existing ones, soft-removing ones no
// longer reported), refresh repository metadata, check for updates, and
// sync package_updates + their linked recommendations. Triggered by the
// admin's [Scan Packages] button (spec §9) and by PackageScanScheduler.
func (s *PackageService) Scan(ctx context.Context, resourceID uuid.UUID) (PackageScanResult, error) {
	vm, err := s.store.GetVMByResourceID(ctx, resourceID)
	if err != nil {
		return PackageScanResult{}, fmt.Errorf("load vm: %w", err)
	}

	client, connErr := s.ssh.Connect(ctx, resourceID)
	if outcomeErr := RecordConnectionOutcome(ctx, s.store, resourceID, vm.ID, connErr); outcomeErr != nil {
		return PackageScanResult{}, fmt.Errorf("record connection outcome: %w", outcomeErr)
	}
	if connErr != nil {
		sshErr := classifyConnectError(connErr)
		return s.failRun(ctx, vm.ID, "", "Connection failed: "+sshErr.Message)
	}
	defer client.Close()

	run, err := s.store.CreatePackageDiscoveryRun(ctx, generated.CreatePackageDiscoveryRunParams{
		VmID: vm.ID, PackageManager: pgutil.Text(""),
	})
	if err != nil {
		return PackageScanResult{}, fmt.Errorf("create package discovery run: %w", err)
	}
	scanStart := run.StartedAt.Time

	pmType := s.detector.Detect(ctx, client, pgutil.TextOrEmpty(vm.DistributionID))
	if pmType != PMTypeUnsupported || !vm.PackageManager.Valid {
		// Never overwrite a previously-valid detection with UNSUPPORTED
		// (Step 7 spec §4) -- only write when we detected something real,
		// or there was never a valid value to begin with.
		if _, err := s.store.UpdateVMPackageManager(ctx, generated.UpdateVMPackageManagerParams{
			ID: vm.ID, PackageManager: pgutil.Text(string(pmType)),
		}); err != nil {
			return PackageScanResult{}, fmt.Errorf("update vm package manager: %w", err)
		}
	}
	if pmType == PMTypeUnsupported {
		return s.completeRun(ctx, run.ID, "FAILED", string(pmType), 0, "No supported package manager detected (APT/DNF/YUM).")
	}

	manager := s.factory.New(pmType)
	installed, err := manager.ListInstalledPackages(ctx, client)
	if err != nil {
		return s.completeRun(ctx, run.ID, "FAILED", string(pmType), 0, "Could not list installed packages: "+safeErrorMessage(err))
	}

	packageByKey := make(map[string]uuid.UUID, len(installed))
	installedByKey := make(map[string]InstalledPackage, len(installed))
	for _, pkg := range installed {
		row, err := s.store.UpsertPackage(ctx, generated.UpsertPackageParams{
			VmID: vm.ID, Name: pkg.Name, InstalledVersion: pkg.Version,
			PackageManager: string(pmType), Architecture: nonEmptyOr(pkg.Architecture, "unknown"),
			Description: pgutil.Text(pkg.Description),
			InstalledAt:  pgutil.TimestamptzFromPtr(pkg.InstalledAt),
		})
		if err != nil {
			return PackageScanResult{}, fmt.Errorf("upsert package %s: %w", pkg.Name, err)
		}
		key := packageKey(pkg.Name, nonEmptyOr(pkg.Architecture, "unknown"))
		packageByKey[key] = row.ID
		installedByKey[key] = pkg
	}
	if err := s.store.MarkPackagesRemovedSince(ctx, generated.MarkPackagesRemovedSinceParams{
		VmID: vm.ID, LastDiscoveredAt: pgutil.Timestamptz(scanStart),
	}); err != nil {
		return PackageScanResult{}, fmt.Errorf("mark removed packages: %w", err)
	}

	// The baseline only needs a successful package *inventory* (the upsert
	// loop above), which is already done by this point -- it has nothing
	// to do with whether update metadata could also be refreshed below.
	// Gating this on the update-check outcome too (i.e. only on "SUCCESS",
	// never "PARTIAL") meant a VM whose SSH user simply lacks passwordless
	// "apt-get update" access -- an extremely common, otherwise-harmless
	// permission gap -- would NEVER get a baseline stamped at all, no
	// matter how many times it was rescanned, silently breaking the
	// "Installed Since Onboarding" feature end to end for that VM.
	if err := s.store.SetVMPackageBaselineIfUnset(ctx, vm.ID); err != nil {
		return PackageScanResult{}, fmt.Errorf("set package baseline: %w", err)
	}

	updateCount, updateErr := s.checkAndSyncUpdates(ctx, resourceID, vm.ID, manager, client, packageByKey, installedByKey, scanStart)

	status := "SUCCESS"
	errorSummary := ""
	if updateErr != nil {
		status = "PARTIAL"
		errorSummary = "Package inventory updated, but update information could not be refreshed: " + safeErrorMessage(updateErr)
	}
	return s.completeRun(ctx, run.ID, status, string(pmType), len(installed), errorSummary, updateCount)
}

// RefreshUpdates re-checks for available updates against the
// already-known package inventory, without re-listing installed
// packages (spec §29's separate, lighter POST .../packages/refresh).
func (s *PackageService) RefreshUpdates(ctx context.Context, resourceID uuid.UUID) (PackageScanResult, error) {
	vm, err := s.store.GetVMByResourceID(ctx, resourceID)
	if err != nil {
		return PackageScanResult{}, fmt.Errorf("load vm: %w", err)
	}
	if !vm.PackageManager.Valid || vm.PackageManager.String == string(PMTypeUnsupported) || vm.PackageManager.String == "" {
		return PackageScanResult{Status: "FAILED", ErrorSummary: "No package manager detected yet -- run a full scan first."}, nil
	}
	pmType := PackageManagerType(vm.PackageManager.String)

	client, connErr := s.ssh.Connect(ctx, resourceID)
	if outcomeErr := RecordConnectionOutcome(ctx, s.store, resourceID, vm.ID, connErr); outcomeErr != nil {
		return PackageScanResult{}, fmt.Errorf("record connection outcome: %w", outcomeErr)
	}
	if connErr != nil {
		sshErr := classifyConnectError(connErr)
		return s.failRun(ctx, vm.ID, string(pmType), "Connection failed: "+sshErr.Message)
	}
	defer client.Close()

	run, err := s.store.CreatePackageDiscoveryRun(ctx, generated.CreatePackageDiscoveryRunParams{
		VmID: vm.ID, PackageManager: pgutil.Text(string(pmType)),
	})
	if err != nil {
		return PackageScanResult{}, fmt.Errorf("create package discovery run: %w", err)
	}
	scanStart := run.StartedAt.Time

	existing, err := s.store.ListPackagesByVM(ctx, vm.ID)
	if err != nil {
		return PackageScanResult{}, fmt.Errorf("load existing packages: %w", err)
	}
	packageByKey := make(map[string]uuid.UUID, len(existing))
	installedByKey := make(map[string]InstalledPackage, len(existing))
	for _, p := range existing {
		if p.RemovedAt.Valid {
			continue
		}
		key := packageKey(p.Name, p.Architecture)
		packageByKey[key] = p.ID
		installedByKey[key] = InstalledPackage{Name: p.Name, Version: p.InstalledVersion, Architecture: p.Architecture}
	}

	manager := s.factory.New(pmType)
	updateCount, updateErr := s.checkAndSyncUpdates(ctx, resourceID, vm.ID, manager, client, packageByKey, installedByKey, scanStart)
	if updateErr != nil {
		return s.completeRun(ctx, run.ID, "FAILED", string(pmType), len(existing), "Update information could not be refreshed: "+safeErrorMessage(updateErr))
	}
	return s.completeRun(ctx, run.ID, "SUCCESS", string(pmType), len(existing), "", updateCount)
}

// checkAndSyncUpdates refreshes metadata, checks for updates, and
// synchronizes package_updates + their linked recommendations (spec
// §19/§48): every currently-available update is upserted (updating an
// existing row in place rather than duplicating it); anything not seen
// this run is resolved. Returns the number of active updates after
// syncing.
func (s *PackageService) checkAndSyncUpdates(
	ctx context.Context, resourceID, vmRowID uuid.UUID, manager PackageManager, client *ssh.Client,
	packageByKey map[string]uuid.UUID, installedByKey map[string]InstalledPackage, scanStart time.Time,
) (int, error) {
	if err := manager.RefreshMetadata(ctx, client); err != nil {
		return 0, err
	}
	updates, err := manager.CheckUpdates(ctx, client)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, u := range updates {
		key := packageKey(u.Name, u.Architecture)
		packageID, ok := packageByKey[key]
		if !ok {
			// The package manager reported an update for something not in
			// our installed list (arch mismatch, or a package that
			// disappeared between the two commands) -- skip rather than
			// guess which installed row it belongs to.
			continue
		}
		installed := installedByKey[key]
		severity := "UNKNOWN"
		if u.SecurityStatus == SecurityConfirmed {
			// Confirmed security updates get elevated priority without
			// claiming a specific severity level we have no evidence for
			// (spec §17).
			severity = "HIGH"
		}

		row, err := s.store.UpsertPackageUpdate(ctx, generated.UpsertPackageUpdateParams{
			VmID: vmRowID, PackageID: packageID, CurrentVersion: installed.Version, AvailableVersion: u.AvailableVersion,
			Severity: severity, IsSecurityUpdate: u.SecurityStatus == SecurityConfirmed, SecurityStatus: string(u.SecurityStatus),
			Architecture: pgutil.Text(u.Architecture), Release: pgutil.Text(u.Release),
		})
		if err != nil {
			return count, fmt.Errorf("upsert package update for %s: %w", u.Name, err)
		}
		count++

		metadata := map[string]any{
			"package": u.Name, "installed_version": installed.Version, "available_version": u.AvailableVersion,
			"security_update": u.SecurityStatus == SecurityConfirmed,
		}
		metadataJSON, _ := json.Marshal(metadata)
		if _, err := s.store.UpsertRecommendationBySource(ctx, generated.UpsertRecommendationBySourceParams{
			ResourceID: resourceID, Type: "PACKAGE_UPDATE", Severity: severity,
			Title:       fmt.Sprintf("%s update available", u.Name),
			Description: pgutil.Text(fmt.Sprintf("Installed version %s, available version %s.", installed.Version, u.AvailableVersion)),
			Metadata:    metadataJSON,
			SourceType:  pgutil.Text("package_update"), SourceID: pgutil.NullUUID(&row.ID),
		}); err != nil {
			return count, fmt.Errorf("upsert recommendation for %s: %w", u.Name, err)
		}
	}

	resolved, err := s.store.ResolvePackageUpdatesNotSeenSince(ctx, generated.ResolvePackageUpdatesNotSeenSinceParams{
		VmID: vmRowID, DetectedAt: pgutil.Timestamptz(scanStart),
	})
	if err != nil {
		return count, fmt.Errorf("resolve stale package updates: %w", err)
	}
	for _, r := range resolved {
		if err := s.store.ResolveRecommendationBySource(ctx, generated.ResolveRecommendationBySourceParams{
			SourceType: pgutil.Text("package_update"), SourceID: pgutil.NullUUID(&r.ID),
		}); err != nil {
			return count, fmt.Errorf("resolve recommendation for package update %s: %w", r.ID, err)
		}
	}

	return count, nil
}

func (s *PackageService) failRun(ctx context.Context, vmRowID uuid.UUID, pmType, errorSummary string) (PackageScanResult, error) {
	run, err := s.store.CreatePackageDiscoveryRun(ctx, generated.CreatePackageDiscoveryRunParams{
		VmID: vmRowID, PackageManager: pgutil.Text(pmType),
	})
	if err != nil {
		return PackageScanResult{}, fmt.Errorf("create package discovery run: %w", err)
	}
	return s.completeRun(ctx, run.ID, "FAILED", pmType, 0, errorSummary)
}

func (s *PackageService) completeRun(ctx context.Context, runID uuid.UUID, status, pmType string, packageCount int, errorSummary string, updateCount ...int) (PackageScanResult, error) {
	if _, err := s.store.CompletePackageDiscoveryRun(ctx, generated.CompletePackageDiscoveryRunParams{
		ID: runID, Status: status, PackageCount: pgutil.Int4(int32(packageCount)), ErrorSummary: pgutil.Text(errorSummary),
	}); err != nil {
		return PackageScanResult{}, fmt.Errorf("complete package discovery run: %w", err)
	}
	uc := 0
	if len(updateCount) > 0 {
		uc = updateCount[0]
	}
	return PackageScanResult{
		Status: status, PackageManager: PackageManagerType(pmType), PackageCount: packageCount,
		UpdateCount: uc, ErrorSummary: errorSummary,
	}, nil
}

func packageKey(name, architecture string) string {
	return name + "\x00" + architecture
}

func nonEmptyOr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// dsnCredentialPattern matches a connection-string credential fragment
// ("scheme://user:password@") that could end up embedded in a raw driver
// error -- e.g. a malformed-DSN parse error from database_operation_run.go's
// fresh direct-database connection attempts. Most drivers (pgx, go-sql-
// driver/mysql) already redact credentials from their own error messages,
// but that is an external, implicit guarantee this codebase should not
// rely on alone.
var dsnCredentialPattern = regexp.MustCompile(`://[^/\s:@]+:[^/\s@]*@`)

// safeErrorMessage returns err's message with any embedded connection-
// string credentials redacted, safe to log, audit, or return to a caller.
func safeErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	return dsnCredentialPattern.ReplaceAllString(err.Error(), "://***:***@")
}
