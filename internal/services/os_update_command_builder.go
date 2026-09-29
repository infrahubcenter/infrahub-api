package services

import (
	"regexp"
	"strings"
)

// This file generates command *strings* only, for preview -- spec
// #52/#53's explicit "Command Builder -> Command Preview" architecture,
// deliberately separate from any execution path (that's Step 10's
// "Command Builder -> Execution Engine -> SSH -> VM" chain, not built
// here). No type in this file holds a *RemoteExecutor or *ssh.Client, and
// no method takes one -- there is structurally no way for anything here
// to run a command, only to describe one as a string.

// UpdateCommandBuilder builds the exact command that would be run to
// apply a set of selected package updates, for a specific package
// manager family. Every returned command is backend-generated from
// package names already stored in this project's own database -- never
// built from a raw command string a client submitted (spec #30).
type UpdateCommandBuilder interface {
	Type() PackageManagerType
	BuildPackageUpdateCommand(packageNames []string) string
	BuildKernelUpdateCommand(packageNames []string) string
	// BuildOSReleaseCommand returns the OS release-upgrade command for
	// distributionID, if one exists. ok is false when no safe, universal
	// release-upgrade command exists for this distribution (spec #32's
	// example is Ubuntu-only; every other distribution honestly reports
	// "no command available" rather than a guessed one).
	BuildOSReleaseCommand(distributionID string) (command string, ok bool)
}

// safePackageNamePattern validates a package name before it's ever
// placed into a generated command-preview string. These names originate
// from this project's own `packages` table (populated from dpkg-query/
// rpm -qa output, Step 7), not user input -- but Step 8 established the
// discipline of validating every remote-sourced value used to build a
// command string regardless of its origin, and this file follows the
// same rule. A name that fails validation is simply omitted from the
// generated command rather than included unsafely.
var safePackageNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:~-]*$`)

func safeCommandPackageNames(names []string) []string {
	safe := make([]string, 0, len(names))
	for _, n := range names {
		if safePackageNamePattern.MatchString(n) {
			safe = append(safe, n)
		}
	}
	return safe
}

// UpdateCommandBuilderFactory builds an UpdateCommandBuilder for a
// detected package manager type, mirroring PackageManagerFactory's exact
// shape (Step 7).
type UpdateCommandBuilderFactory struct{}

// NewUpdateCommandBuilderFactory creates an UpdateCommandBuilderFactory.
func NewUpdateCommandBuilderFactory() *UpdateCommandBuilderFactory {
	return &UpdateCommandBuilderFactory{}
}

// New returns the UpdateCommandBuilder for pmType, or nil for
// PMTypeUnsupported (callers must check).
func (f *UpdateCommandBuilderFactory) New(pmType PackageManagerType) UpdateCommandBuilder {
	switch pmType {
	case PMTypeAPT:
		return APTCommandBuilder{}
	case PMTypeDNF:
		return DNFCommandBuilder{}
	case PMTypeYUM:
		return YUMCommandBuilder{}
	default:
		return nil
	}
}

// --- APT ---

// APTCommandBuilder implements UpdateCommandBuilder for Debian/Ubuntu.
type APTCommandBuilder struct{}

func (APTCommandBuilder) Type() PackageManagerType { return PMTypeAPT }

func (APTCommandBuilder) BuildPackageUpdateCommand(packageNames []string) string {
	safe := safeCommandPackageNames(packageNames)
	if len(safe) == 0 {
		return ""
	}
	// --only-upgrade is the deliberate choice here: it refuses to install
	// a package that isn't already installed, so this command can never
	// accidentally add new software even if a stale/mismatched package
	// name were ever passed in -- it only ever upgrades what's already
	// present (spec #29's exact example command).
	return "apt-get install --only-upgrade " + strings.Join(safe, " ")
}

func (b APTCommandBuilder) BuildKernelUpdateCommand(packageNames []string) string {
	// A kernel package is installed the same way as any other APT
	// package -- no separate verb exists.
	return b.BuildPackageUpdateCommand(packageNames)
}

func (APTCommandBuilder) BuildOSReleaseCommand(distributionID string) (string, bool) {
	if distributionID != "ubuntu" {
		return "", false
	}
	return "do-release-upgrade", true
}

// --- DNF ---

// DNFCommandBuilder implements UpdateCommandBuilder for Fedora/RHEL 8+/
// Rocky/AlmaLinux/current CentOS.
type DNFCommandBuilder struct{}

func (DNFCommandBuilder) Type() PackageManagerType { return PMTypeDNF }

func (DNFCommandBuilder) BuildPackageUpdateCommand(packageNames []string) string {
	safe := safeCommandPackageNames(packageNames)
	if len(safe) == 0 {
		return ""
	}
	return "dnf upgrade " + strings.Join(safe, " ")
}

func (b DNFCommandBuilder) BuildKernelUpdateCommand(packageNames []string) string {
	return b.BuildPackageUpdateCommand(packageNames)
}

func (DNFCommandBuilder) BuildOSReleaseCommand(string) (string, bool) {
	// No universal, safe, read-only-to-generate release-upgrade command
	// exists across the RPM family without additional tooling (e.g.
	// `leapp`) that itself makes system changes just by being installed
	// -- honestly reporting "not available" rather than guessing one.
	return "", false
}

// --- YUM ---

// YUMCommandBuilder implements UpdateCommandBuilder for RHEL/CentOS 7
// and Amazon Linux 2.
type YUMCommandBuilder struct{}

func (YUMCommandBuilder) Type() PackageManagerType { return PMTypeYUM }

func (YUMCommandBuilder) BuildPackageUpdateCommand(packageNames []string) string {
	safe := safeCommandPackageNames(packageNames)
	if len(safe) == 0 {
		return ""
	}
	return "yum update " + strings.Join(safe, " ")
}

func (b YUMCommandBuilder) BuildKernelUpdateCommand(packageNames []string) string {
	return b.BuildPackageUpdateCommand(packageNames)
}

func (YUMCommandBuilder) BuildOSReleaseCommand(string) (string, bool) {
	return "", false
}
