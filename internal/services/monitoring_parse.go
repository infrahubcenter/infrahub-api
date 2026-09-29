package services

import (
	"strconv"
	"strings"
)

// This file holds every Linux monitoring-command output parser (Step 6
// spec §55): each accepts raw command stdout and returns a typed
// structure plus an ok bool, and touches nothing SSH-related -- kept
// separate from the collector specifically so it's unit-testable against
// fixture strings without a VM (spec §56).

// --- CPU (/proc/stat) ---

// CPUStat is one /proc/stat "cpu " line's raw jiffie counters. Fields
// beyond steal (guest, guest_nice) are intentionally not modeled: they're
// already included in user/nice on the host's accounting and Step 6 spec
// §11 only lists user..steal for the total.
type CPUStat struct {
	User, Nice, System, Idle, IOWait, IRQ, SoftIRQ, Steal int64
}

// Total sums every counter that contributes to total_delta (spec §11).
func (c CPUStat) Total() int64 {
	return c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
}

// ParseProcStat reads the aggregate "cpu " line from /proc/stat output.
// Kernels vary in how many fields they report (very old kernels omit
// iowait/irq/softirq/steal entirely) -- any field not present is treated
// as 0 rather than failing the whole parse.
func ParseProcStat(output string) (CPUStat, bool) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "cpu ") && !strings.HasPrefix(line, "cpu\t") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 { // "cpu" + at least user/nice/system/idle
			return CPUStat{}, false
		}
		nums := make([]int64, 8)
		for i := 1; i < len(fields) && i <= 8; i++ {
			v, err := strconv.ParseInt(fields[i], 10, 64)
			if err != nil {
				return CPUStat{}, false
			}
			nums[i-1] = v
		}
		return CPUStat{
			User: nums[0], Nice: nums[1], System: nums[2], Idle: nums[3],
			IOWait: nums[4], IRQ: nums[5], SoftIRQ: nums[6], Steal: nums[7],
		}, true
	}
	return CPUStat{}, false
}

// CountCPUCores counts the per-core "cpuN " lines in the same /proc/stat
// output ParseProcStat reads, avoiding a second command just for a core
// count -- and staying accurate if the VM was resized since the last
// discovery run, unlike falling back to the discovery-recorded value.
func CountCPUCores(output string) int32 {
	var cores int32
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if len(line) < 4 || line[:3] != "cpu" {
			continue
		}
		rest := line[3:]
		spaceIdx := strings.IndexAny(rest, " \t")
		if spaceIdx <= 0 {
			continue
		}
		if _, err := strconv.Atoi(rest[:spaceIdx]); err == nil {
			cores++
		}
	}
	return cores
}

// CPUUsage is the percentage breakdown computed from two CPUStat samples.
type CPUUsage struct {
	UsagePercent, UserPercent, SystemPercent, IOWaitPercent, IdlePercent float64
}

// ComputeCPUUsage implements Step 6 spec §10-12: usage is always a delta
// between two samples, never a single read. Returns ok=false whenever the
// delta isn't usable (first sample, clock went backwards, or a
// zero/negative total delta) -- callers must store NULL rather than a
// fabricated number in that case (spec §12).
func ComputeCPUUsage(prev, curr CPUStat) (CPUUsage, bool) {
	totalDelta := curr.Total() - prev.Total()
	if totalDelta <= 0 {
		return CPUUsage{}, false
	}
	pct := func(delta int64) float64 {
		if delta < 0 {
			delta = 0
		}
		v := 100 * float64(delta) / float64(totalDelta)
		return clampPercent(v)
	}
	idleDelta := curr.Idle - prev.Idle
	return CPUUsage{
		UsagePercent:  clampPercent(100 * (1 - float64(max64(idleDelta, 0))/float64(totalDelta))),
		UserPercent:   pct(curr.User - prev.User),
		SystemPercent: pct(curr.System - prev.System),
		IOWaitPercent: pct(curr.IOWait - prev.IOWait),
		IdlePercent:   pct(idleDelta),
	}, true
}

func clampPercent(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// --- Memory (/proc/meminfo) ---

// MemoryMetrics is derived from /proc/meminfo. HasSwap is false when the
// VM has no swap configured at all (SwapTotal absent or zero) -- Step 6
// spec §15 requires this to render as "Not configured", not a monitoring
// failure.
type MemoryMetrics struct {
	TotalBytes, AvailableBytes, UsedBytes int64
	UsagePercent                          float64
	HasSwap                               bool
	SwapTotalBytes, SwapUsedBytes         int64
	SwapUsagePercent                      float64
}

// ParseMemInfo parses /proc/meminfo. MemTotal and MemAvailable are
// required (spec §13 explicitly forbids substituting MemFree for
// MemAvailable); if the kernel doesn't report MemAvailable at all (pre-3.14,
// effectively never seen in practice today), this returns ok=false rather
// than approximating.
func ParseMemInfo(output string) (MemoryMetrics, bool) {
	values := parseKeyValueKB(output)
	total, hasTotal := values["MemTotal"]
	available, hasAvailable := values["MemAvailable"]
	if !hasTotal || !hasAvailable || total <= 0 {
		return MemoryMetrics{}, false
	}
	if available > total {
		available = total
	}
	used := total - available

	m := MemoryMetrics{
		TotalBytes: total, AvailableBytes: available, UsedBytes: used,
		UsagePercent: clampPercent(100 * float64(used) / float64(total)),
	}

	swapTotal, hasSwapTotal := values["SwapTotal"]
	if hasSwapTotal && swapTotal > 0 {
		swapFree := values["SwapFree"]
		if swapFree > swapTotal {
			swapFree = swapTotal
		}
		m.HasSwap = true
		m.SwapTotalBytes = swapTotal
		m.SwapUsedBytes = swapTotal - swapFree
		m.SwapUsagePercent = clampPercent(100 * float64(m.SwapUsedBytes) / float64(swapTotal))
	}
	return m, true
}

// parseKeyValueKB parses /proc/meminfo's "Key:    12345 kB" lines into a
// map of byte values (kB -> bytes). A line without a trailing unit is
// treated as already being in kB too (meminfo's convention for every
// field that isn't a bare count, e.g. HugePages_Total).
func parseKeyValueKB(output string) map[string]int64 {
	values := make(map[string]int64)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		rest := strings.Fields(strings.TrimSpace(line[colon+1:]))
		if len(rest) == 0 {
			continue
		}
		n, err := strconv.ParseInt(rest[0], 10, 64)
		if err != nil {
			continue
		}
		values[key] = n * 1024
	}
	return values
}

// --- Load average (/proc/loadavg) ---

// ParseLoadAvg parses "1.42 1.12 0.87 3/512 12345".
func ParseLoadAvg(output string) (one, five, fifteen float64, ok bool) {
	fields := strings.Fields(strings.TrimSpace(output))
	if len(fields) < 3 {
		return 0, 0, 0, false
	}
	var err error
	if one, err = strconv.ParseFloat(fields[0], 64); err != nil {
		return 0, 0, 0, false
	}
	if five, err = strconv.ParseFloat(fields[1], 64); err != nil {
		return 0, 0, 0, false
	}
	if fifteen, err = strconv.ParseFloat(fields[2], 64); err != nil {
		return 0, 0, 0, false
	}
	return one, five, fifteen, true
}

// --- Uptime (/proc/uptime) ---

// ParseUptime parses "308522.34 1234.56" (uptime seconds, idle seconds)
// and returns the first field, rounded down to whole seconds.
func ParseUptime(output string) (int64, bool) {
	fields := strings.Fields(strings.TrimSpace(output))
	if len(fields) < 1 {
		return 0, false
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || seconds < 0 {
		return 0, false
	}
	return int64(seconds), true
}

// --- Filesystems (df -PkT) ---

// FilesystemEntry is one mounted filesystem's usage, straight from `df`.
type FilesystemEntry struct {
	MountPoint     string
	Filesystem     string // device/source, df's first column
	Type           string // df -T's TYPE column
	TotalBytes     int64
	UsedBytes      int64
	AvailableBytes int64
	UsagePercent   float64
}

// pseudoFilesystemTypes are excluded from monitoring by default (Step 6
// spec §19): virtual/kernel bookkeeping filesystems that never represent
// real disk capacity. This is a blocklist, not an allowlist, specifically
// so real filesystem types this list doesn't anticipate (ext4, xfs, btrfs,
// zfs, nfs, overlay/overlay2 -- including Docker's own storage --
// ntfs, vfat, ...) are never accidentally hidden (spec §19's explicit
// warning). Documented verbatim in docs/vm-monitoring.md.
var pseudoFilesystemTypes = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true,
	"tmpfs": true, "cgroup": true, "cgroup2": true, "mqueue": true,
	"pstore": true, "securityfs": true, "debugfs": true, "configfs": true,
	"fusectl": true, "hugetlbfs": true, "tracefs": true, "binfmt_misc": true,
	"autofs": true, "rpc_pipefs": true, "nsfs": true, "bpf": true,
}

// ParseDF parses `df -PkT` output (POSIX-portable 1K-block sizing with the
// filesystem-type column). Handles the common case where a long device
// name pushes the rest of the line onto the next one (frequent with
// overlay2/docker mounts) by treating a data line with only one field as
// "device name only" and merging it with the line that follows.
func ParseDF(output string) []FilesystemEntry {
	lines := strings.Split(output, "\n")
	var entries []FilesystemEntry
	pending := ""
	for i, raw := range lines {
		if i == 0 {
			continue // header: "Filesystem Type 1024-blocks Used Available Capacity Mounted on"
		}
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if pending != "" {
			fields = append([]string{pending}, fields...)
			pending = ""
		}
		if len(fields) == 1 {
			pending = fields[0]
			continue
		}
		if len(fields) < 6 {
			continue
		}
		total, err1 := strconv.ParseInt(fields[2], 10, 64)
		used, err2 := strconv.ParseInt(fields[3], 10, 64)
		avail, err3 := strconv.ParseInt(fields[4], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		pctField := strings.TrimSuffix(fields[5], "%")
		pct, err := strconv.ParseFloat(pctField, 64)
		if err != nil {
			// Some filesystems (e.g. zero-capacity pseudo mounts) render "-".
			if total > 0 {
				pct = clampPercent(100 * float64(used) / float64(total))
			}
		}
		mount := strings.Join(fields[6:], " ")
		if mount == "" {
			continue
		}
		entries = append(entries, FilesystemEntry{
			MountPoint: mount, Filesystem: fields[0], Type: fields[1],
			TotalBytes: total * 1024, UsedBytes: used * 1024, AvailableBytes: avail * 1024,
			UsagePercent: clampPercent(pct),
		})
	}
	return entries
}

// FilterFilesystems drops pseudo filesystems per pseudoFilesystemTypes.
func FilterFilesystems(entries []FilesystemEntry) []FilesystemEntry {
	filtered := make([]FilesystemEntry, 0, len(entries))
	for _, e := range entries {
		if pseudoFilesystemTypes[e.Type] {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

// --- Network (/proc/net/dev) ---

// NetworkInterfaceSample is one interface's cumulative counters from one
// /proc/net/dev read.
type NetworkInterfaceSample struct {
	Name                                    string
	RxBytes, RxPackets, RxErrors, RxDropped int64
	TxBytes, TxPackets, TxErrors, TxDropped int64
}

// ParseNetDev parses /proc/net/dev. The loopback interface ("lo") is
// dropped here, at the source, rather than merely excluded from
// aggregates -- Step 6 spec §24 treats it as noise for every VM-level
// network metric, and there's no monitoring use for storing it per-VM.
func ParseNetDev(output string) []NetworkInterfaceSample {
	var samples []NetworkInterfaceSample
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, ":") {
			continue // header lines ("Inter-|...", " face |...")
		}
		parts := strings.SplitN(line, ":", 2)
		name := strings.TrimSpace(parts[0])
		if name == "" || name == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}
		parse := func(s string) int64 {
			v, _ := strconv.ParseInt(s, 10, 64)
			return v
		}
		samples = append(samples, NetworkInterfaceSample{
			Name:      name,
			RxBytes:   parse(fields[0]),
			RxPackets: parse(fields[1]),
			RxErrors:  parse(fields[2]),
			RxDropped: parse(fields[3]),
			TxBytes:   parse(fields[8]),
			TxPackets: parse(fields[9]),
			TxErrors:  parse(fields[10]),
			TxDropped: parse(fields[11]),
		})
	}
	return samples
}

// NetworkRate is a delta-derived rate between two samples of the same
// interface, in bytes/sec.
type NetworkRate struct {
	RxBytesPerSec, TxBytesPerSec float64
}

// ComputeNetworkRate mirrors ComputeCPUUsage: never derived from a single
// cumulative read, ok=false on the first sample or a non-positive time
// delta (spec §25).
func ComputeNetworkRate(prev, curr NetworkInterfaceSample, elapsedSeconds float64) (NetworkRate, bool) {
	if elapsedSeconds <= 0 {
		return NetworkRate{}, false
	}
	rxDelta := curr.RxBytes - prev.RxBytes
	txDelta := curr.TxBytes - prev.TxBytes
	if rxDelta < 0 {
		rxDelta = 0
	}
	if txDelta < 0 {
		txDelta = 0
	}
	return NetworkRate{
		RxBytesPerSec: float64(rxDelta) / elapsedSeconds,
		TxBytesPerSec: float64(txDelta) / elapsedSeconds,
	}, true
}

// --- Process summary (ps -eo stat=) ---

// ProcessSummary is a coarse process-state count (spec §27) -- never a
// full per-process listing.
type ProcessSummary struct {
	Total, Running, Sleeping, Zombie int
}

// ParsePS parses the bare STAT column from `ps -eo stat=` (one state code
// per line, e.g. "Ss", "R+", "Z"). Only the first character is
// significant: R=running, S/D=sleeping (interruptible/uninterruptible),
// Z=zombie. Any other leading state (T=stopped, I=idle kernel thread, ...)
// counts toward Total but not the three named buckets.
func ParsePS(output string) (ProcessSummary, bool) {
	var s ProcessSummary
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		s.Total++
		switch line[0] {
		case 'R':
			s.Running++
		case 'S', 'D':
			s.Sleeping++
		case 'Z':
			s.Zombie++
		}
	}
	if s.Total == 0 {
		return ProcessSummary{}, false
	}
	return s, true
}
