package services

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// This file holds every package-manager output parser (Step 7 spec §55):
// pure functions from raw command stdout to typed structures, with no SSH
// involved -- unit-tested against fixture strings in
// package_parse_test.go, exactly like monitoring_parse.go in Step 6.

// InstalledPackage is one package as reported by the target VM's package
// database. Architecture is always populated (never left ambiguous) so
// e.g. libfoo:amd64 and libfoo:i386 are never collapsed into one record
// (spec §7).
type InstalledPackage struct {
	Name         string
	Version      string
	Architecture string
	Description  string
	// InstalledAt is the package manager's own record of when this
	// package was actually installed on the box (nil when the package
	// manager can't report one) -- see packages.installed_at's doc
	// comment in migration 054 for why this is distinct from (and more
	// trustworthy than) our own scanner's discovery time.
	InstalledAt *time.Time
}

// SecurityStatus mirrors the package_updates.security_status column
// (Step 7 spec §15): CONFIRMED only when real package-manager/repository
// evidence says so, never guessed from a package's name.
type SecurityStatus string

const (
	SecurityConfirmed   SecurityStatus = "CONFIRMED"
	SecurityNotSecurity SecurityStatus = "NOT_SECURITY"
	SecurityUnknown     SecurityStatus = "UNKNOWN"
)

// AvailableUpdate is one package's update situation as reported by the
// package manager's update-check command.
type AvailableUpdate struct {
	Name             string
	AvailableVersion string
	Architecture     string
	Release          string // RPM only; empty for Debian (release lives inside AvailableVersion there)
	SecurityStatus   SecurityStatus
}

// --- Debian/APT (dpkg-query, apt list --upgradable) ---

// ParseDpkgQuery parses the output of:
//
//	dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n'
//
// One line per installed package. Description is intentionally never
// collected from dpkg-query: dpkg's ${Description} field is multi-line
// (breaking this format entirely) and there is no single-line
// alternative guaranteed present on every dpkg-query version this
// project targets -- see docs/package-management.md's documented
// decision to leave Debian package descriptions empty rather than risk a
// parse failure across the whole installed-package list for a
// nice-to-have field.
func ParseDpkgQuery(output string) []InstalledPackage {
	var packages []InstalledPackage
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		version := strings.TrimSpace(fields[1])
		arch := strings.TrimSpace(fields[2])
		if name == "" || version == "" {
			continue
		}
		packages = append(packages, InstalledPackage{Name: name, Version: version, Architecture: arch})
	}
	return packages
}

// aptUpgradableLine matches a line from `apt list --upgradable`, e.g.:
//
//	nginx/jammy-security 1.26.2-0ubuntu1 amd64 [upgradable from: 1.24.0-2ubuntu7]
var aptUpgradableLine = regexp.MustCompile(`^(\S+)/(\S+)\s+(\S+)\s+(\S+)\s+\[upgradable from:\s*([^\]]+)\]`)

// ParseAptUpgradable parses `apt list --upgradable` output. Security
// classification (spec §15) is based on real evidence: the release/pocket
// name apt itself reports (the part after '/') -- e.g. "jammy-security"
// -- not a guess from the package name. Absence of "-security" in that
// field is not proof an update *isn't* security-related (Ubuntu
// sometimes ships fixes via -updates too), so it's classified UNKNOWN,
// never NOT_SECURITY, without stronger evidence.
func ParseAptUpgradable(output string) []AvailableUpdate {
	var updates []AvailableUpdate
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Listing...") {
			continue
		}
		m := aptUpgradableLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name, pocket, availableVersion, arch := m[1], m[2], m[3], m[4]
		security := SecurityUnknown
		if strings.Contains(strings.ToLower(pocket), "-security") {
			security = SecurityConfirmed
		}
		updates = append(updates, AvailableUpdate{
			Name: name, AvailableVersion: availableVersion, Architecture: arch, SecurityStatus: security,
		})
	}
	return updates
}

// --- RPM family (rpm -qa, dnf/yum check-update) ---

// ParseRPMQA parses:
//
//	rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SUMMARY}\t%{INSTALLTIME}\n'
//
// %{SUMMARY} (unlike dpkg's ${Description}) is guaranteed single-line by
// the RPM format spec, so it's safe to include here. %{INSTALLTIME} is the
// RPM database's own epoch-seconds install timestamp -- always present for
// a real rpm build, unlike dpkg which has no equivalent field at all.
func ParseRPMQA(output string) []InstalledPackage {
	var packages []InstalledPackage
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 5)
		if len(fields) < 3 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		versionRelease := strings.TrimSpace(fields[1])
		arch := strings.TrimSpace(fields[2])
		if name == "" || versionRelease == "" {
			continue
		}
		pkg := InstalledPackage{Name: name, Version: versionRelease, Architecture: arch}
		if len(fields) >= 4 {
			pkg.Description = strings.TrimSpace(fields[3])
		}
		if len(fields) >= 5 {
			if epoch, err := strconv.ParseInt(strings.TrimSpace(fields[4]), 10, 64); err == nil && epoch > 0 {
				t := time.Unix(epoch, 0).UTC()
				pkg.InstalledAt = &t
			}
		}
		packages = append(packages, pkg)
	}
	return packages
}

// dpkgInfoListFile matches one line of:
//
//	stat -c '%Y %n' /var/lib/dpkg/info/*.list
//
// e.g. "1690000000 /var/lib/dpkg/info/libc6:amd64.list" -- the mtime, then
// the path. The optional ":arch" suffix (present for multi-arch packages)
// is stripped since InstalledPackage keys match by bare package name here
// (dpkg-query's ${Package} field never includes it either).
var dpkgInfoListFile = regexp.MustCompile(`^(\d+)\s+.*/([^/]+)\.list$`)

// ParseDpkgInstallTimes parses `stat -c '%Y %n' /var/lib/dpkg/info/*.list`
// output into a name -> install-time map, for ListInstalledPackages to
// join against ParseDpkgQuery's result by package name. Best-effort: a
// package with no matching .list entry (or an unparseable line) simply
// isn't in the returned map.
func ParseDpkgInstallTimes(output string) map[string]time.Time {
	times := make(map[string]time.Time)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		m := dpkgInfoListFile.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		epoch, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			continue
		}
		name := m[2]
		if idx := strings.IndexByte(name, ':'); idx >= 0 {
			name = name[:idx] // strip ":amd64" etc.
		}
		t := time.Unix(epoch, 0).UTC()
		// Multiple .list files can map to the same bare name only in
		// exotic multi-arch setups; keep the earliest, which is the
		// closer approximation to "first installed".
		if existing, ok := times[name]; !ok || t.Before(existing) {
			times[name] = t
		}
	}
	return times
}

// checkUpdateLine matches one non-header line from `dnf check-update` /
// `yum check-update`, e.g.:
//
//	openssl.x86_64          1:3.0.7-25.el9_2          baseos
//	kernel.x86_64           5.14.0-362.el9            baseos
var checkUpdateLine = regexp.MustCompile(`^(\S+)\.(\S+)\s+(\S+)\s+(\S+)\s*$`)

// ParseCheckUpdate parses `dnf`/`yum check-update` output (identical
// format for both tools). securityPackageNames, when non-nil, is the set
// of "name.arch" strings from a matching `check-update --security` run
// (spec §15/§42): present there -> CONFIRMED, absent -> UNKNOWN (there is
// no reliable "definitely not security" signal from a plain check-update
// alone, so NOT_SECURITY is never inferred here). A nil map (the
// security-specific command wasn't run, or failed) means every update's
// security_status is UNKNOWN.
func ParseCheckUpdate(output string, securityPackageNames map[string]bool) []AvailableUpdate {
	var updates []AvailableUpdate
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// dnf/yum print informational/progress lines before the package
		// table ("Last metadata expiration check: ...", "Obsoleting Packages", ...);
		// only lines matching name.arch VERSION-RELEASE REPO are real entries.
		m := checkUpdateLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name, arch, versionRelease := m[1], m[2], m[3]
		version, release := splitDebianRevision(versionRelease) // last-hyphen split; same mechanic RPM release uses

		security := SecurityUnknown
		if securityPackageNames != nil {
			if securityPackageNames[name+"."+arch] {
				security = SecurityConfirmed
			} else {
				security = SecurityUnknown
			}
		}
		updates = append(updates, AvailableUpdate{
			Name: name, AvailableVersion: version, Architecture: arch, Release: release, SecurityStatus: security,
		})
	}
	return updates
}

// ParseCheckUpdateSecurityNames extracts the "name.arch" set from a
// `dnf`/`yum check-update --security` run, for ParseCheckUpdate's
// securityPackageNames parameter.
func ParseCheckUpdateSecurityNames(output string) map[string]bool {
	names := make(map[string]bool)
	for _, u := range ParseCheckUpdate(output, nil) {
		names[u.Name+"."+u.Architecture] = true
	}
	return names
}
