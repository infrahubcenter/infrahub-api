package services

import "fmt"

// ComputeDatabasePerformanceHealth folds deep-cycle evidence (locks,
// cache hit ratio, replication lag, query p95 latency) on top of the
// exact fast-metrics health computation, and builds a human-readable
// reasons list (spec §43/#123: "more useful than a single misleading
// score"). deep may be nil (no deep cycle has completed yet); in that
// case the result is exactly ComputeDatabaseHealth's own verdict with no
// deep-derived reasons -- never a fabricated reason from missing data.
func ComputeDatabasePerformanceHealth(
	common CommonMetrics, maxMemoryBytes int64, connectionStatus ConnectionTestStatus, fastThresholds DatabaseHealthThresholds,
	deep *DeepMetricsSample, perfThresholds DatabasePerformanceThresholds,
) (HealthStatus, []string) {
	health := ComputeDatabaseHealth(common, maxMemoryBytes, connectionStatus, fastThresholds)
	var reasons []string

	if common.Connections != nil && common.MaxConnections != nil && *common.MaxConnections > 0 {
		pct := float64(*common.Connections) / float64(*common.MaxConnections) * 100
		if pct >= fastThresholds.ConnectionWarning {
			reasons = append(reasons, fmt.Sprintf("Connection utilization is %.0f%%.", pct))
		}
	}
	if deep == nil {
		return health, reasons
	}

	if deep.Locks.Blocked != nil && *deep.Locks.Blocked > 0 {
		reasons = append(reasons, fmt.Sprintf("%d session(s) are blocked.", *deep.Locks.Blocked))
		health = worseDatabaseHealth(health, lockContentionSeverity(*deep.Locks.Blocked, perfThresholds.LockWarningCount))
	}
	if deep.CacheHitRatio != nil && *deep.CacheHitRatio < perfThresholds.CacheHitWarning {
		reasons = append(reasons, fmt.Sprintf("Cache hit ratio is %.1f%%, below the configured threshold.", *deep.CacheHitRatio))
		if *deep.CacheHitRatio < perfThresholds.CacheHitCritical {
			health = worseDatabaseHealth(health, HealthCritical)
		} else {
			health = worseDatabaseHealth(health, HealthWarning)
		}
	}
	if deep.Replication.LagSeconds != nil && *deep.Replication.LagSeconds > 10 {
		reasons = append(reasons, fmt.Sprintf("Replication lag is %.1fs.", *deep.Replication.LagSeconds))
		health = worseDatabaseHealth(health, HealthWarning)
	}
	if deep.LatencyP95Ms != nil && *deep.LatencyP95Ms >= perfThresholds.SlowQueryMs {
		reasons = append(reasons, fmt.Sprintf("Query p95 latency is %.0fms.", *deep.LatencyP95Ms))
		health = worseDatabaseHealth(health, HealthWarning)
	}
	return health, reasons
}

func worseDatabaseHealth(a, b HealthStatus) HealthStatus {
	if healthRank(b) > healthRank(a) {
		return b
	}
	return a
}

func lockContentionSeverity(blocked, warnCount int64) HealthStatus {
	if warnCount <= 0 {
		warnCount = 1
	}
	switch {
	case blocked >= warnCount*2:
		return HealthCritical
	case blocked >= warnCount:
		return HealthWarning
	default:
		return HealthHealthy
	}
}
