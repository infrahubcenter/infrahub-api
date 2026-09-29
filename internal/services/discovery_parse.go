package services

import (
	"strconv"
	"strings"
)

// parseOSRelease reads /etc/os-release (or any compatible os-release
// file) and extracts the fields Step 5 stores. It is intentionally
// generic -- no assumption that the distribution is Ubuntu (§25): any
// standards-compliant os-release file (Debian, RHEL/Fedora, Alpine,
// Arch, ...) parses the same way.
func parseOSRelease(output string) (name, version, distributionID string) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, `"`)
		switch key {
		case "NAME":
			name = value
		case "VERSION":
			version = value
		case "ID":
			distributionID = value
		}
	}
	return name, version, distributionID
}

// parseMemTotalBytes reads /proc/meminfo and returns MemTotal in bytes.
// Deliberately ignores MemAvailable and every other field -- Step 5 only
// stores total capacity; utilization is a later (monitoring) step's job
// (§30).
func parseMemTotalBytes(output string) (int64, bool) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "MemTotal:" {
			continue
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return kb * 1024, true
	}
	return 0, false
}

// parseDFTotalBytes reads `df -Pk /` output (POSIX-mode, 1024-byte
// blocks, single-line-per-filesystem) and returns the root filesystem's
// total capacity in bytes.
//
// This reports the root filesystem only, not a sum across every mount --
// summing arbitrary mounts risks double-counting bind mounts/overlays and
// picking up unrelated volumes; per-mount detail is what the (separate,
// not-yet-built) vm_filesystems table is for (§31).
func parseDFTotalBytes(output string) (int64, bool) {
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	if len(lines) < 2 {
		return 0, false
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 2 {
		return 0, false
	}
	blocks, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return blocks * 1024, true
}

// parseCPUCores reads `nproc` output.
func parseCPUCores(output string) (int32, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(output), 10, 32)
	if err != nil || n <= 0 {
		return 0, false
	}
	return int32(n), true
}
