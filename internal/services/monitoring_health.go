package services

// HealthStatus is monitoring health -- deliberately a different
// vocabulary from resources.status (UNKNOWN/ONLINE/OFFLINE/WARNING/ERROR/
// DISABLED) and vms.connection_status, per Step 6 spec §35/§36: an SSH
// connection can be CONNECTED while health is CRITICAL (high disk usage),
// and neither of those things ever flips resources.status.
type HealthStatus string

const (
	HealthHealthy  HealthStatus = "HEALTHY"
	HealthWarning  HealthStatus = "WARNING"
	HealthCritical HealthStatus = "CRITICAL"
	HealthUnknown  HealthStatus = "UNKNOWN"
	HealthOffline  HealthStatus = "OFFLINE"
)

// HealthThresholds are the configured warning/critical percentages (Step 6
// spec §21-23), loaded once from config and passed down rather than read
// from the environment deep inside the collector.
type HealthThresholds struct {
	CPUWarning, CPUCritical       float64
	MemoryWarning, MemoryCritical float64
	DiskWarning, DiskCritical     float64
}

func severityRank(s HealthStatus) int {
	switch s {
	case HealthCritical:
		return 2
	case HealthWarning:
		return 1
	default:
		return 0
	}
}

// dimensionStatus evaluates one current value against a warning/critical
// pair. A nil value (metric wasn't collected this cycle) is simply
// excluded by the caller rather than treated as a verdict here.
func dimensionStatus(value float64, warning, critical float64) HealthStatus {
	switch {
	case value >= critical:
		return HealthCritical
	case value >= warning:
		return HealthWarning
	default:
		return HealthHealthy
	}
}

// cpuDimensionStatus implements Step 6 spec §23's explicit requirement:
// "do not declare a VM unhealthy based on one temporary CPU spike if
// avoidable... prefer a short evaluation window or consecutive samples."
//
// Chosen approach (documented in docs/vm-monitoring.md): look at up to the
// 3 most recent CPU samples, newest first, including the one just
// computed this cycle. WARNING/CRITICAL is only reported when at least 2
// consecutive recent samples all breach that threshold -- a single spike
// (one high sample surrounded by normal ones) reports HEALTHY. With fewer
// than 2 samples available (the VM's first or second collection ever),
// there isn't enough history to call anything "sustained" yet, so this
// also reports HEALTHY rather than guessing from one point.
func cpuDimensionStatus(recentSamplesNewestFirst []float64, warning, critical float64) HealthStatus {
	n := len(recentSamplesNewestFirst)
	if n > 3 {
		n = 3
	}
	window := recentSamplesNewestFirst[:n]
	if len(window) < 2 {
		return HealthHealthy
	}
	allCritical, allWarning := true, true
	for _, v := range window {
		if v < critical {
			allCritical = false
		}
		if v < warning {
			allWarning = false
		}
	}
	switch {
	case allCritical:
		return HealthCritical
	case allWarning:
		return HealthWarning
	default:
		return HealthHealthy
	}
}

// ComputeSnapshotHealth is called once per successful collection cycle
// (Step 6 spec §35) using only the data from that cycle plus recent CPU
// history for the anti-flap check above. It only ever returns HEALTHY,
// WARNING, CRITICAL, or UNKNOWN -- OFFLINE is never stored on a snapshot
// (a snapshot only exists because the SSH connection that produced it
// succeeded); it's applied afterward, at read time, from the VM's current
// connection state -- see DeriveDisplayHealth.
func ComputeSnapshotHealth(cpuPercent, memoryPercent, diskPercent *float64, cpuHistoryNewestFirst []float64, t HealthThresholds) HealthStatus {
	worst := HealthHealthy
	known := false

	if cpuPercent != nil {
		known = true
		if s := cpuDimensionStatus(cpuHistoryNewestFirst, t.CPUWarning, t.CPUCritical); severityRank(s) > severityRank(worst) {
			worst = s
		}
	}
	if memoryPercent != nil {
		known = true
		if s := dimensionStatus(*memoryPercent, t.MemoryWarning, t.MemoryCritical); severityRank(s) > severityRank(worst) {
			worst = s
		}
	}
	if diskPercent != nil {
		known = true
		if s := dimensionStatus(*diskPercent, t.DiskWarning, t.DiskCritical); severityRank(s) > severityRank(worst) {
			worst = s
		}
	}

	if !known {
		return HealthUnknown
	}
	return worst
}

// DeriveDisplayHealth is what the API actually returns for "current
// health" (Step 6 spec §35-36): connection state always wins over a
// possibly-stale stored health value, and "never collected" always wins
// over both.
func DeriveDisplayHealth(hasSnapshot bool, connectionHealthy bool, storedHealth HealthStatus) HealthStatus {
	if !hasSnapshot {
		return HealthUnknown
	}
	if !connectionHealthy {
		return HealthOffline
	}
	return storedHealth
}
