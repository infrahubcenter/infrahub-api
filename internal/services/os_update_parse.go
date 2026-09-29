package services

import (
	"regexp"
	"strconv"
	"strings"
)

// This file holds every pure parser Update Center's OS/kernel/reboot
// detection needs (Step 9 spec): no SSH involved, unit-tested against
// fixture strings, exactly like discovery_parse.go/monitoring_parse.go/
// docker_parse.go. Update Center re-reads /etc/os-release fresh rather
// than trusting Step 5's already-stored os_name/os_version -- the same
// "detect independently, don't assume stale state is still true"
// discipline Step 8 established for Docker daemon status.

// OSReleaseInfo is a fuller read of /etc/os-release than Step 5's
// discovery needs (spec #6 wants a release channel, which needs the raw
// VERSION field, not just NAME/VERSION already stored on vms).
type OSReleaseInfo struct {
	Name            string
	Version         string // e.g. "24.04.3 LTS (Noble Numbat)"
	VersionID       string // e.g. "24.04"
	VersionCodename string // e.g. "noble"
	ID              string // e.g. "ubuntu"
}

// ParseOSReleaseFull parses /etc/os-release (or any compatible file).
func ParseOSReleaseFull(output string) (OSReleaseInfo, bool) {
	var info OSReleaseInfo
	found := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, `"`)
		found = true
		switch key {
		case "NAME":
			info.Name = value
		case "VERSION":
			info.Version = value
		case "VERSION_ID":
			info.VersionID = value
		case "VERSION_CODENAME":
			info.VersionCodename = value
		case "ID":
			info.ID = value
		}
	}
	return info, found
}

// ReleaseChannel infers spec #6's release_channel from the raw VERSION
// string -- real evidence (Ubuntu's own os-release literally includes
// the substring "LTS" for LTS releases), never a fabricated guess. Only
// implemented for Ubuntu, where this evidence exists; every other
// distribution reports "unknown" rather than a guessed value.
func ReleaseChannel(distributionID, version string) string {
	if distributionID != "ubuntu" {
		return "unknown"
	}
	if strings.Contains(strings.ToUpper(version), "LTS") {
		return "LTS"
	}
	if version == "" {
		return "unknown"
	}
	return "non-LTS"
}

// ReleaseUpgradeCheck is the result of `do-release-upgrade -c` (Ubuntu's
// own read-only "is a new release available" check -- it never performs
// the upgrade itself, spec #4/#5's exact requirement).
type ReleaseUpgradeCheck struct {
	Available  bool
	NewRelease string // e.g. "24.04", empty if Available is false
}

var doReleaseUpgradeAvailablePattern = regexp.MustCompile(`New release '([^']+)' available`)

// ParseDoReleaseUpgradeCheck parses `do-release-upgrade -c`'s stdout.
// Detection is text-based (the documented "New release '<X>' available"
// message), not exit-code-based -- do-release-upgrade's exit codes are
// not consistently documented across versions, while this message format
// is its own long-stable, user-facing contract.
func ParseDoReleaseUpgradeCheck(output string) ReleaseUpgradeCheck {
	if m := doReleaseUpgradeAvailablePattern.FindStringSubmatch(output); m != nil {
		return ReleaseUpgradeCheck{Available: true, NewRelease: m[1]}
	}
	return ReleaseUpgradeCheck{Available: false}
}

// RebootCheck is the result of Debian/Ubuntu's own reboot-required
// indicator files (spec #11's named example paths).
type RebootCheck struct {
	Required bool
	Packages []string // from /var/run/reboot-required.pkgs, if present
}

// ParseDebianRebootCheck parses the output of a combined read of
// /var/run/reboot-required (existence) and /var/run/reboot-required.pkgs
// (contents) -- see the exact shell one-liner in os_update_service.go.
// First line is REQUIRED or NOT_REQUIRED; any further lines are the
// package names that triggered the requirement, one per line.
func ParseDebianRebootCheck(output string) (RebootCheck, bool) {
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	if len(lines) == 0 {
		return RebootCheck{}, false
	}
	switch strings.TrimSpace(lines[0]) {
	case "REQUIRED":
		var pkgs []string
		for _, l := range lines[1:] {
			l = strings.TrimSpace(l)
			if l != "" {
				pkgs = append(pkgs, l)
			}
		}
		return RebootCheck{Required: true, Packages: pkgs}, true
	case "NOT_REQUIRED":
		return RebootCheck{Required: false}, true
	default:
		return RebootCheck{}, false
	}
}

// isAPTKernelImageName matches Debian/Ubuntu's versioned kernel image
// package names (e.g. "linux-image-6.8.0-40-generic") -- deliberately
// excludes meta-packages like "linux-image-generic" (no leading digit
// after the dash), which track "whatever the latest is" rather than
// naming one specific installed kernel.
var isAPTKernelImageName = regexp.MustCompile(`^linux-image-\d`)

// aptKernelImagePrefix strips to exactly this, e.g. "linux-image-" ->
// suffix "6.8.0-40-generic", which is directly comparable to `uname -r`'s
// output as a literal string -- Debian/Ubuntu's own naming convention
// guarantees the two match character-for-character for the same kernel.
const aptKernelImagePrefix = "linux-image-"

// IsKernelPackageName reports whether name is a kernel package for the
// given package manager family (spec #9's detection target).
func IsKernelPackageName(name string, pmType PackageManagerType) bool {
	switch pmType {
	case PMTypeAPT:
		return isAPTKernelImageName.MatchString(name)
	case PMTypeDNF, PMTypeYUM:
		return name == "kernel" || name == "kernel-core"
	default:
		return false
	}
}

// ExtractKernelVersion returns the kernel-version string a package
// row actually represents, directly comparable to `uname -r`'s output.
// For APT it's the versioned suffix of the package name itself (the
// installed_version column tracks the *package's* version, e.g.
// "6.8.0-40.40", not the kernel ABI string `uname -r` reports -- the
// name suffix is what matches). For RPM the package's own
// installed_version already is that string.
func ExtractKernelVersion(pkgName, installedVersion string, pmType PackageManagerType) (string, bool) {
	switch pmType {
	case PMTypeAPT:
		if !isAPTKernelImageName.MatchString(pkgName) {
			return "", false
		}
		return strings.TrimPrefix(pkgName, aptKernelImagePrefix), true
	case PMTypeDNF, PMTypeYUM:
		if pkgName != "kernel" && pkgName != "kernel-core" {
			return "", false
		}
		return installedVersion, true
	default:
		return "", false
	}
}

var kernelVersionSegmentPattern = regexp.MustCompile(`\d+`)

// CompareKernelVersions compares two kernel ABI version strings (e.g.
// "6.8.0-40-generic") by their leading numeric segments. These are
// kernel ABI strings, not package version strings, so package_version.go's
// Debian/RPM comparators (designed for "40.40"/"427.31.1.el9_4"-style
// package versions) don't apply cleanly here -- this is a deliberately
// simpler, purpose-built comparison, good enough to order the handful of
// kernel candidates a VM ever has installed/pending at once. Returns true
// if a is newer than b.
func CompareKernelVersions(a, b string) bool {
	as := kernelVersionSegmentPattern.FindAllString(a, -1)
	bs := kernelVersionSegmentPattern.FindAllString(b, -1)
	for i := 0; i < len(as) && i < len(bs); i++ {
		av, aErr := strconv.Atoi(as[i])
		bv, bErr := strconv.Atoi(bs[i])
		if aErr != nil || bErr != nil {
			break
		}
		if av != bv {
			return av > bv
		}
	}
	if len(as) != len(bs) {
		return len(as) > len(bs)
	}
	return a > b
}
