package services

import "errors"

// ConnectionTestStatus is the connectivity outcome of a direct TCP/TLS
// connection attempt to a standalone database -- deliberately distinct
// from the database's own service state (which this project never
// observes directly for a standalone/managed database, only through
// whether a connection can be made and a health-check query answered).
type ConnectionTestStatus string

const (
	ConnCONNECTED   ConnectionTestStatus = "CONNECTED"
	ConnAUTHFAILED  ConnectionTestStatus = "AUTH_FAILED"
	ConnTIMEOUT     ConnectionTestStatus = "TIMEOUT"
	ConnREFUSED     ConnectionTestStatus = "REFUSED"
	ConnTLSERROR    ConnectionTestStatus = "TLS_ERROR"
	ConnUNAVAILABLE ConnectionTestStatus = "UNAVAILABLE"
	ConnUNKNOWN     ConnectionTestStatus = "UNKNOWN"
)

// ConnectionStatusFromError classifies a direct-connection error into a
// ConnectionTestStatus -- callers persist/display the resulting status,
// never the raw Go error (which could contain a connection string).
func ConnectionStatusFromError(err error) ConnectionTestStatus {
	switch {
	case err == nil:
		return ConnCONNECTED
	case errors.Is(err, ErrDatabaseAuth):
		return ConnAUTHFAILED
	case errors.Is(err, ErrDatabaseTimeout):
		return ConnTIMEOUT
	case errors.Is(err, ErrDatabaseTLS):
		return ConnTLSERROR
	case errors.Is(err, ErrDatabaseConnection):
		return ConnREFUSED
	default:
		return ConnUNKNOWN
	}
}

// DatabaseHealthThresholds are the configurable percent thresholds (spec
// #63/#67) driving rule-based health classification -- never hardcoded
// inline, always read from config.go/env vars. Reuses the exact
// dimensionStatus two-branch rule (monitoring_health.go, Step 6) and the
// shared HealthStatus vocabulary (HEALTHY/WARNING/CRITICAL/UNKNOWN/
// OFFLINE) rather than inventing a second health model.
type DatabaseHealthThresholds struct {
	ConnectionWarning, ConnectionCritical float64
	MemoryWarning, MemoryCritical         float64
}

// ComputeDatabaseHealth derives a rule-based (never a single misleading
// numeric score, spec #62) health status from whichever metrics are
// actually available. A metric that couldn't be read is simply skipped
// -- never treated as 0% or 100% (spec #67: "do not blindly apply
// thresholds when the metric does not exist"). maxMemoryBytes is passed
// in separately (rather than read from CommonMetrics, which has no such
// field -- spec #48: not every engine reports one, and where it does it
// lives in metric_details, e.g. Redis's "max_memory_bytes") and is
// callable with 0/absent to mean "no real limit," matching Redis's own
// "do not show a fake percentage when max memory is unlimited" rule
// (spec #45), applied generically since other engines share the shape.
func ComputeDatabaseHealth(common CommonMetrics, maxMemoryBytes int64, connectionStatus ConnectionTestStatus, t DatabaseHealthThresholds) HealthStatus {
	switch connectionStatus {
	case ConnAUTHFAILED, ConnREFUSED, ConnUNAVAILABLE, ConnTIMEOUT, ConnTLSERROR:
		return HealthOffline
	case ConnUNKNOWN:
		return HealthUnknown
	}

	worst := HealthHealthy
	worsen := func(s HealthStatus) {
		if healthRank(s) > healthRank(worst) {
			worst = s
		}
	}

	if common.Connections != nil && common.MaxConnections != nil && *common.MaxConnections > 0 {
		pct := float64(*common.Connections) / float64(*common.MaxConnections) * 100
		worsen(dimensionStatus(pct, t.ConnectionWarning, t.ConnectionCritical))
	}
	if common.MemoryUsageBytes != nil && maxMemoryBytes > 0 {
		pct := float64(*common.MemoryUsageBytes) / float64(maxMemoryBytes) * 100
		worsen(dimensionStatus(pct, t.MemoryWarning, t.MemoryCritical))
	}

	return worst
}

func healthRank(s HealthStatus) int {
	switch s {
	case HealthHealthy:
		return 0
	case HealthUnknown:
		return 1
	case HealthWarning:
		return 2
	case HealthCritical, HealthOffline:
		return 3
	default:
		return 1
	}
}
