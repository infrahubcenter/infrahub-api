package services

import (
	"context"
	"time"

	"golang.org/x/crypto/ssh"
)

// PackageManagerType identifies a detected package manager family (Step 7
// spec §1/§3). Stored directly on vms.package_manager.
type PackageManagerType string

const (
	PMTypeAPT         PackageManagerType = "APT"
	PMTypeDNF         PackageManagerType = "DNF"
	PMTypeYUM         PackageManagerType = "YUM"
	PMTypeUnsupported PackageManagerType = "UNSUPPORTED"
)

// PackageManager abstracts one package-manager family's read-only
// operations (Step 7 spec §2). No VM handler or scheduler code ever
// branches on package-manager type directly -- everything goes through
// this interface, obtained from PackageManagerFactory.
type PackageManager interface {
	Type() PackageManagerType
	// RefreshMetadataCommand returns the exact command RefreshMetadata (or,
	// for the RPM family, CheckUpdates) will run -- used for the
	// admin-facing command preview (spec §42), never accepted as input.
	RefreshMetadataCommand() string
	ListInstalledPackages(ctx context.Context, client *ssh.Client) ([]InstalledPackage, error)
	// RefreshMetadata refreshes repository metadata only -- never
	// installs, upgrades, or removes anything (spec §10/§11/§12). For the
	// RPM family this is a no-op: check-update refreshes metadata as a
	// side effect, so there is no separate metadata-only verb to call.
	RefreshMetadata(ctx context.Context, client *ssh.Client) error
	CheckUpdates(ctx context.Context, client *ssh.Client) ([]AvailableUpdate, error)
}

// PackageManagerFactory builds a PackageManager for a detected type.
type PackageManagerFactory struct {
	executor       *RemoteExecutor
	commandTimeout time.Duration
}

// NewPackageManagerFactory creates a PackageManagerFactory.
func NewPackageManagerFactory(executor *RemoteExecutor, commandTimeout time.Duration) *PackageManagerFactory {
	return &PackageManagerFactory{executor: executor, commandTimeout: commandTimeout}
}

// New returns the PackageManager for pmType, or nil for
// PMTypeUnsupported (callers must check).
func (f *PackageManagerFactory) New(pmType PackageManagerType) PackageManager {
	switch pmType {
	case PMTypeAPT:
		return &APTManager{executor: f.executor, commandTimeout: f.commandTimeout}
	case PMTypeDNF:
		return newDNFManager(f.executor, f.commandTimeout)
	case PMTypeYUM:
		return newYUMManager(f.executor, f.commandTimeout)
	default:
		return nil
	}
}

// detectionCandidate is one (probe command, resulting type) pair the
// detector tries in order.
type detectionCandidate struct {
	probeBinary string
	pmType      PackageManagerType
}

// PackageManagerDetector determines a VM's package manager (Step 7 §3).
// It never runs every possible tool's probe unconditionally: the
// distribution ID Step 5's discovery already recorded picks a short,
// specific candidate order, so an Ubuntu VM only ever runs one `command
// -v apt-get` check, never also checks for dnf/yum. Only a VM with an
// unrecognized/empty distribution ID falls back to probing all three
// families (still a small, bounded set of read-only `command -v` checks
// -- never any install/upgrade command).
type PackageManagerDetector struct {
	executor       *RemoteExecutor
	commandTimeout time.Duration
}

// NewPackageManagerDetector creates a PackageManagerDetector.
func NewPackageManagerDetector(executor *RemoteExecutor, commandTimeout time.Duration) *PackageManagerDetector {
	return &PackageManagerDetector{executor: executor, commandTimeout: commandTimeout}
}

// Detect returns the detected package manager type for a VM whose
// discovered distribution ID (Step 5's /etc/os-release ID field, e.g.
// "ubuntu", "rhel", "rocky") is distributionID. PMTypeUnsupported is a
// normal, non-error outcome (spec §3: "do not mark the VM itself
// offline") -- it is returned, never wrapped in an error, when no
// supported package manager is found.
func (d *PackageManagerDetector) Detect(ctx context.Context, client *ssh.Client, distributionID string) PackageManagerType {
	for _, candidate := range candidateOrderForDistro(distributionID) {
		if d.commandExists(ctx, client, candidate.probeBinary) {
			return candidate.pmType
		}
	}
	return PMTypeUnsupported
}

func (d *PackageManagerDetector) commandExists(ctx context.Context, client *ssh.Client, binary string) bool {
	res, err := d.executor.Execute(ctx, client, "command -v "+binary, d.commandTimeout)
	return err == nil && res.ExitCode == 0
}

// candidateOrderForDistro maps a distro ID to the package manager
// families worth probing, in priority order. Not an exhaustive distro
// database -- just enough to satisfy spec §44's named families (Ubuntu,
// Debian, RHEL, Rocky, AlmaLinux, CentOS, Fedora) without probing tools
// that distro would never have.
func candidateOrderForDistro(distributionID string) []detectionCandidate {
	apt := detectionCandidate{"apt-get", PMTypeAPT}
	dnf := detectionCandidate{"dnf", PMTypeDNF}
	yum := detectionCandidate{"yum", PMTypeYUM}

	switch distributionID {
	case "ubuntu", "debian", "linuxmint", "pop", "raspbian", "elementary", "kali", "zorin", "neon":
		return []detectionCandidate{apt}
	case "fedora":
		return []detectionCandidate{dnf}
	case "rhel", "rocky", "almalinux", "centos", "ol", "amzn":
		// RHEL 8+/Rocky/Alma/current CentOS all ship dnf; older
		// CentOS/RHEL 7 and Amazon Linux 2 only have yum -- dnf first,
		// yum as the fallback within this same family.
		return []detectionCandidate{dnf, yum}
	default:
		// Unrecognized or empty distribution ID: fall back to checking
		// for any of the three, in the most-common-first order.
		return []detectionCandidate{apt, dnf, yum}
	}
}
