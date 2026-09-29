package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Fixed, backend-authored, read-only-with-respect-to-installed-software
// commands (Step 7 spec §10-12, §41-42). apt-get update / dnf check-update
// / yum check-update all change *local repository metadata* -- never
// installed packages -- which is exactly why they're treated as
// information operations here, admin-gated but never mistaken for an
// upgrade. None of these strings are ever built from user input.
const (
	aptListInstalledCmd = `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n'`
	aptRefreshCmd       = "apt-get update"
	aptCheckUpdatesCmd  = "apt list --upgradable"
	// dpkg has no per-package "install date" field, but /var/lib/dpkg/info/
	// is written exactly once at install/configure time and untouched
	// afterward -- its mtime is the same trick apt's own changelog tooling
	// and countless "when was X installed" shell one-liners use. 2>/dev/null
	// so an empty/missing info dir (never happens in practice, but keep the
	// list itself from failing) just yields no install-time data rather
	// than a non-zero exit.
	aptListInstallTimesCmd = `stat -c '%Y %n' /var/lib/dpkg/info/*.list 2>/dev/null`
	rpmListInstalledCmd    = `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SUMMARY}\t%{INSTALLTIME}\n'`
)

// safeCommandError renders a failed command's exit code and a truncated
// stderr snippet -- bounded length as a defensive habit, even though
// package-manager tool output never contains credentials.
func safeCommandError(context string, exitCode int, stderr string) error {
	stderr = strings.TrimSpace(stderr)
	if len(stderr) > 300 {
		stderr = stderr[:300] + "…"
	}
	if stderr == "" {
		return fmt.Errorf("%s exited with status %d", context, exitCode)
	}
	return fmt.Errorf("%s exited with status %d: %s", context, exitCode, stderr)
}

// isPrivilegeError recognizes the common "you need to be root" stderr
// signatures apt/dnf/yum produce, so a permission problem can be reported
// clearly (spec §43) instead of a generic failure. This never triggers
// any automatic sudo/privilege-escalation attempt -- it only changes the
// wording of the error surfaced to the admin.
func isPrivilegeError(stderr string) bool {
	lower := strings.ToLower(stderr)
	signatures := []string{
		"permission denied",
		"are you root",
		"must be run as root",
		"must be superuser",
		"superuser privileges",
		"could not open lock file",
		"unable to lock the administration directory",
	}
	for _, s := range signatures {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func privilegeErrorMessage(pmType PackageManagerType, command string) error {
	return fmt.Errorf(
		"the configured SSH user does not have permission to run %q for %s metadata refresh; "+
			"this application never attempts automatic privilege escalation -- grant the SSH user "+
			"passwordless access to this specific read-only operation if metadata refresh is needed",
		command, pmType,
	)
}

// --- APT ---

// APTManager implements PackageManager for Debian/Ubuntu-family systems.
type APTManager struct {
	executor       *RemoteExecutor
	commandTimeout time.Duration
}

func (m *APTManager) Type() PackageManagerType       { return PMTypeAPT }
func (m *APTManager) RefreshMetadataCommand() string { return aptRefreshCmd }

func (m *APTManager) ListInstalledPackages(ctx context.Context, client *ssh.Client) ([]InstalledPackage, error) {
	res, err := m.executor.Execute(ctx, client, aptListInstalledCmd, m.commandTimeout)
	if err != nil {
		return nil, fmt.Errorf("list installed packages: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, safeCommandError("dpkg-query", res.ExitCode, res.Stderr)
	}
	packages := ParseDpkgQuery(res.Stdout)

	// Best-effort only: a failure here (unreadable dir, exotic dpkg setup)
	// must never fail the whole inventory scan -- it just means every
	// package's InstalledAt stays nil and callers fall back to discovery
	// time, exactly as if this command didn't exist at all.
	if timesRes, timesErr := m.executor.Execute(ctx, client, aptListInstallTimesCmd, m.commandTimeout); timesErr == nil && timesRes.ExitCode == 0 {
		installTimes := ParseDpkgInstallTimes(timesRes.Stdout)
		for i := range packages {
			if t, ok := installTimes[packages[i].Name]; ok {
				packages[i].InstalledAt = &t
			}
		}
	}
	return packages, nil
}

// RefreshMetadata runs `apt-get update` -- spec §10 is explicit that this
// exact command is a package-*information* operation, not an
// installation/upgrade, despite modifying local repository metadata.
func (m *APTManager) RefreshMetadata(ctx context.Context, client *ssh.Client) error {
	res, err := m.executor.Execute(ctx, client, aptRefreshCmd, m.commandTimeout)
	if err != nil {
		return fmt.Errorf("refresh metadata: %w", err)
	}
	if res.ExitCode != 0 {
		if isPrivilegeError(res.Stderr) {
			return privilegeErrorMessage(PMTypeAPT, aptRefreshCmd)
		}
		return safeCommandError(aptRefreshCmd, res.ExitCode, res.Stderr)
	}
	return nil
}

func (m *APTManager) CheckUpdates(ctx context.Context, client *ssh.Client) ([]AvailableUpdate, error) {
	res, err := m.executor.Execute(ctx, client, aptCheckUpdatesCmd, m.commandTimeout)
	if err != nil {
		return nil, fmt.Errorf("check updates: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, safeCommandError(aptCheckUpdatesCmd, res.ExitCode, res.Stderr)
	}
	return ParseAptUpgradable(res.Stdout), nil
}

// --- DNF / YUM (RPM family) ---

// rpmFamilyManager implements PackageManager for both DNF and YUM: the
// two tools' CLI surface for the read-only operations this step needs
// (list installed via rpm, check-update, check-update --security) is
// identical apart from the binary name, so sharing one implementation
// avoids duplicating the same parsing/error-handling logic twice.
// DNFManager and YUMManager below are the distinct named types the
// architecture calls for; each is a thin constructor over this shared
// core.
type rpmFamilyManager struct {
	pmType         PackageManagerType
	binary         string
	executor       *RemoteExecutor
	commandTimeout time.Duration
}

func (m *rpmFamilyManager) Type() PackageManagerType { return m.pmType }
func (m *rpmFamilyManager) RefreshMetadataCommand() string {
	return m.binary + " check-update"
}

func (m *rpmFamilyManager) ListInstalledPackages(ctx context.Context, client *ssh.Client) ([]InstalledPackage, error) {
	res, err := m.executor.Execute(ctx, client, rpmListInstalledCmd, m.commandTimeout)
	if err != nil {
		return nil, fmt.Errorf("list installed packages: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, safeCommandError("rpm -qa", res.ExitCode, res.Stderr)
	}
	return ParseRPMQA(res.Stdout), nil
}

// RefreshMetadata is a no-op for the RPM family: neither dnf nor yum has
// a metadata-only verb distinct from check-update -- check-update itself
// refreshes metadata as a side effect (spec §12: "use the appropriate
// metadata operation without applying package changes"), so the actual
// refresh happens inside CheckUpdates below.
func (m *rpmFamilyManager) RefreshMetadata(ctx context.Context, client *ssh.Client) error {
	return nil
}

// checkUpdateExitOK reports whether an exit code from `dnf`/`yum
// check-update` represents success -- these tools use a non-standard
// convention where 100 means "ran fine, updates ARE available", not an
// error.
func checkUpdateExitOK(exitCode int) bool { return exitCode == 0 || exitCode == 100 }

func (m *rpmFamilyManager) CheckUpdates(ctx context.Context, client *ssh.Client) ([]AvailableUpdate, error) {
	command := m.binary + " check-update"
	res, err := m.executor.Execute(ctx, client, command, m.commandTimeout)
	if err != nil {
		return nil, fmt.Errorf("check updates: %w", err)
	}
	if !checkUpdateExitOK(res.ExitCode) {
		if isPrivilegeError(res.Stderr) {
			return nil, privilegeErrorMessage(m.pmType, command)
		}
		return nil, safeCommandError(command, res.ExitCode, res.Stderr)
	}

	// Security classification is best-effort: if the --security variant
	// fails (older yum without the security plugin, etc.), every update
	// from the main check-update result simply stays SecurityUnknown --
	// spec §15's graceful degradation, not a failure of the whole scan.
	var securityNames map[string]bool
	secCommand := command + " --security"
	if secRes, secErr := m.executor.Execute(ctx, client, secCommand, m.commandTimeout); secErr == nil && checkUpdateExitOK(secRes.ExitCode) {
		securityNames = ParseCheckUpdateSecurityNames(secRes.Stdout)
	}

	return ParseCheckUpdate(res.Stdout, securityNames), nil
}

// DNFManager is PackageManager for DNF (Fedora, RHEL 8+/Rocky/AlmaLinux).
type DNFManager struct{ *rpmFamilyManager }

func newDNFManager(executor *RemoteExecutor, commandTimeout time.Duration) *DNFManager {
	return &DNFManager{&rpmFamilyManager{pmType: PMTypeDNF, binary: "dnf", executor: executor, commandTimeout: commandTimeout}}
}

// YUMManager is PackageManager for YUM (RHEL/CentOS 7, Amazon Linux 2).
type YUMManager struct{ *rpmFamilyManager }

func newYUMManager(executor *RemoteExecutor, commandTimeout time.Duration) *YUMManager {
	return &YUMManager{&rpmFamilyManager{pmType: PMTypeYUM, binary: "yum", executor: executor, commandTimeout: commandTimeout}}
}
