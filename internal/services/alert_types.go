package services

// AlertType is the closed set of predefined alert templates (spec §40).
// Never a free-text type -- every alert traces back to exactly one of
// these, each pre-bound to a specific AlertMetric so an Admin configuring
// a rule from a template can't accidentally mismatch metric and type.
type AlertType string

const (
	AlertTypeVMHighCPU     AlertType = "VM_HIGH_CPU"
	AlertTypeVMHighMemory  AlertType = "VM_HIGH_MEMORY"
	AlertTypeVMHighStorage AlertType = "VM_HIGH_STORAGE"
	AlertTypeVMUnavailable AlertType = "VM_UNAVAILABLE"

	AlertTypeDockerContainerStopped    AlertType = "DOCKER_CONTAINER_STOPPED"
	AlertTypeDockerContainerRestarting AlertType = "DOCKER_CONTAINER_RESTARTING"
	AlertTypeDockerContainerUnhealthy  AlertType = "DOCKER_CONTAINER_UNHEALTHY"
	// AlertTypeDockerContainerOOM exists in the schema/type system for
	// forward compatibility (spec §40 explicitly lists it) but is never
	// evaluated by the engine today -- Docker's OOM-kill flag isn't
	// captured anywhere in this project's docker_containers schema
	// (Step 8), so there is no honest metric to back it yet, the same
	// "declared but unsupported" precedent as Step 14's RESTART/UPGRADE
	// operation types.
	AlertTypeDockerContainerOOM AlertType = "DOCKER_CONTAINER_OOM"

	AlertTypeDatabaseUnavailable     AlertType = "DATABASE_UNAVAILABLE"
	AlertTypeDatabaseHighConnections AlertType = "DATABASE_HIGH_CONNECTIONS"
	AlertTypeDatabaseHighLatency     AlertType = "DATABASE_HIGH_LATENCY"
	AlertTypeDatabaseLockContention  AlertType = "DATABASE_LOCK_CONTENTION"
	AlertTypeDatabaseReplicationLag  AlertType = "DATABASE_REPLICATION_LAG"
	AlertTypeDatabaseHighStorage     AlertType = "DATABASE_HIGH_STORAGE"
	AlertTypeDatabaseLowCacheHit     AlertType = "DATABASE_LOW_CACHE_HIT"

	// Object storage (Step 17 Phase 3) -- migration 026 already widened
	// alert_rules.alert_type's CHECK constraint to include these five
	// exact string values.
	AlertTypeObjectStorageUnavailable        AlertType = "OBJECT_STORAGE_UNAVAILABLE"
	AlertTypeObjectStorageHighGrowth         AlertType = "OBJECT_STORAGE_HIGH_GROWTH"
	AlertTypeObjectStoragePublicAccess       AlertType = "OBJECT_STORAGE_PUBLIC_ACCESS"
	AlertTypeObjectStorageEncryptionDisabled AlertType = "OBJECT_STORAGE_ENCRYPTION_DISABLED"
	AlertTypeObjectStorageHighErrorRate      AlertType = "OBJECT_STORAGE_HIGH_ERROR_RATE"

	// Alert Rules widening: Kubernetes pods, standalone Docker Hosts, and
	// log-based alerts (migration 058). AppliesToResource for these is
	// "K8S_POD"/"DOCKER_HOST_CONTAINER" (special-cased in
	// AlertRuleService.Create exactly like "DOCKER_CONTAINER" already is)
	// or plain "DOCKER_HOST" for a host-level rule with no sub-target.
	// AlertTypeK8sClusterUnavailable is cluster-level (applies directly to
	// the K8S_CLUSTER resource, no pod narrowing) -- mirrors
	// AlertTypeDockerHostUnavailable below exactly: agent-disconnected,
	// resolved via K8sAgentHub.IsConnected.
	AlertTypeK8sClusterUnavailable AlertType = "K8S_CLUSTER_UNAVAILABLE"

	AlertTypeK8sPodNotRunning   AlertType = "K8S_POD_NOT_RUNNING"
	AlertTypeK8sPodCrashLooping AlertType = "K8S_POD_CRASH_LOOPING"
	AlertTypeK8sPodHighCPU      AlertType = "K8S_POD_HIGH_CPU"
	AlertTypeK8sPodHighMemory   AlertType = "K8S_POD_HIGH_MEMORY"
	// AlertTypeK8sPodHighErrorLogs/AlertTypeDockerHostContainerHighErrorLogs/
	// AlertTypeDockerContainerHighErrorLogs are the new log-based category:
	// unlike every metric-threshold type above, the "current value" is a
	// count of ERROR/CRITICAL-classified log lines seen within the rule's
	// own duration_seconds window (services.ClassifyLogLine, read-time
	// only -- see alert_metric_lookup.go's alertLogErrorCount), not a
	// numeric sample an existing scheduler already collected.
	AlertTypeK8sPodHighErrorLogs AlertType = "K8S_POD_HIGH_ERROR_LOGS"

	AlertTypeDockerHostUnavailable AlertType = "DOCKER_HOST_UNAVAILABLE"
	// AlertTypeDockerHostContainerHighErrorLogs applies to a Docker Host's
	// own container (docker_host_container_sightings), distinct from
	// AlertTypeDockerContainerHighErrorLogs below (a VM-hosted container).
	AlertTypeDockerHostContainerHighErrorLogs AlertType = "DOCKER_HOST_CONTAINER_HIGH_ERROR_LOGS"
	AlertTypeDockerContainerHighErrorLogs     AlertType = "DOCKER_CONTAINER_HIGH_ERROR_LOGS"
)

// AlertMetric is the closed set of predefined, backend-computed metrics a
// rule can reference (spec §37/§38: "Rules must use predefined metrics,
// operators, thresholds, durations" -- never arbitrary code/SQL/shell).
type AlertMetric string

const (
	MetricCPUPercent     AlertMetric = "CPU_PERCENT"
	MetricMemoryPercent  AlertMetric = "MEMORY_PERCENT"
	MetricStoragePercent AlertMetric = "STORAGE_PERCENT"
	MetricVMUnreachable  AlertMetric = "VM_UNREACHABLE" // 1 = unreachable, 0 = reachable

	MetricContainerStopped      AlertMetric = "CONTAINER_STOPPED" // 1 = exited/dead, 0 = running
	MetricContainerRestarting   AlertMetric = "CONTAINER_RESTARTING"
	MetricContainerUnhealthy    AlertMetric = "CONTAINER_UNHEALTHY"
	MetricContainerRestartCount AlertMetric = "CONTAINER_RESTART_COUNT"

	MetricDBUnreachable        AlertMetric = "DB_UNREACHABLE" // 1 = unreachable, 0 = reachable
	MetricDBConnectionPercent  AlertMetric = "DB_CONNECTION_PERCENT"
	MetricDBLatencyP95Ms       AlertMetric = "DB_LATENCY_P95_MS"
	MetricDBLocksBlocked       AlertMetric = "DB_LOCKS_BLOCKED"
	MetricDBReplicationLagSecs AlertMetric = "DB_REPLICATION_LAG_SECONDS"
	// MetricDBStorageBytes is the database's own reported size in GB (not
	// a percentage -- no capacity is tracked for a standalone/managed
	// database to compute a percentage against, unlike a VM's
	// total_storage_bytes).
	MetricDBStorageBytes    AlertMetric = "DB_STORAGE_BYTES"
	MetricDBCacheHitPercent AlertMetric = "DB_CACHE_HIT_PERCENT"

	// Object storage (Step 17 Phase 3) -- migration 026 already widened
	// alert_rules.metric's CHECK constraint to include these five exact
	// string values.
	MetricObjectStorageUnreachable            AlertMetric = "OBJECT_STORAGE_UNREACHABLE" // 1 = unreachable, 0 = reachable
	MetricObjectStorageGrowthPercent          AlertMetric = "OBJECT_STORAGE_GROWTH_PERCENT"
	MetricObjectStoragePublicAccessFlag       AlertMetric = "OBJECT_STORAGE_PUBLIC_ACCESS_FLAG"       // 1 = PUBLIC, 0 = PRIVATE
	MetricObjectStorageEncryptionDisabledFlag AlertMetric = "OBJECT_STORAGE_ENCRYPTION_DISABLED_FLAG" // 1 = DISABLED, 0 = ENABLED
	MetricObjectStorageErrorRatePercent       AlertMetric = "OBJECT_STORAGE_ERROR_RATE_PERCENT"

	// Kubernetes pods -- resolved from k8s_pods, refreshed every
	// K8S_SCAN_INTERVAL (~10 min) by K8sDiscoveryScheduler, same
	// "read an existing scheduler's own last sample" discipline as every
	// metric above.
	MetricK8sPodUnavailable   AlertMetric = "K8S_POD_UNAVAILABLE" // 1 = phase != RUNNING, 0 = RUNNING
	MetricK8sPodRestartCount  AlertMetric = "K8S_POD_RESTART_COUNT"
	MetricK8sPodCPUMillicores AlertMetric = "K8S_POD_CPU_MILLICORES"
	// MetricK8sPodMemoryBytes resolves in MB, not raw bytes -- a friendlier
	// default threshold number, same "not a percentage, no tracked
	// capacity" reasoning MetricDBStorageBytes already applies (that one
	// resolves in GB despite its own name).
	MetricK8sPodMemoryBytes AlertMetric = "K8S_POD_MEMORY_BYTES"

	// Standalone Docker Hosts -- resolved directly from DockerAgentHub.IsConnected,
	// no scheduler/snapshot involved (an in-memory connection registry check).
	MetricDockerHostUnreachable AlertMetric = "DOCKER_HOST_UNREACHABLE" // 1 = agent disconnected, 0 = connected
	// MetricK8sClusterUnreachable mirrors MetricDockerHostUnreachable,
	// resolved via K8sAgentHub.IsConnected instead.
	MetricK8sClusterUnreachable AlertMetric = "K8S_CLUSTER_UNREACHABLE"

	// Log-based (migration 058): a count of ERROR/CRITICAL-severity lines
	// (services.ClassifyLogLine) seen within the rule's own
	// duration_seconds window -- see alertLogErrorCount.
	MetricK8sPodLogErrorCount              AlertMetric = "K8S_POD_LOG_ERROR_COUNT"
	MetricDockerHostContainerLogErrorCount AlertMetric = "DOCKER_HOST_CONTAINER_LOG_ERROR_COUNT"
	MetricContainerLogErrorCount           AlertMetric = "CONTAINER_LOG_ERROR_COUNT"
)

// AlertCondition is the closed set of comparison operators a rule may
// use (spec §37).
type AlertCondition string

const (
	CondGreaterThan        AlertCondition = ">"
	CondLessThan           AlertCondition = "<"
	CondGreaterThanOrEqual AlertCondition = ">="
	CondLessThanOrEqual    AlertCondition = "<="
	CondEqual              AlertCondition = "=="
)

// Evaluate applies the condition to (value, threshold) -- the entire
// "rule evaluation" surface a configured alert rule can exercise; there
// is no other code path from a rule's stored fields to a boolean
// decision (spec §38: no shell/SQL/Redis/MongoDB commands are ever
// reachable from an alert rule).
func (c AlertCondition) Evaluate(value, threshold float64) bool {
	switch c {
	case CondGreaterThan:
		return value > threshold
	case CondLessThan:
		return value < threshold
	case CondGreaterThanOrEqual:
		return value >= threshold
	case CondLessThanOrEqual:
		return value <= threshold
	case CondEqual:
		return value == threshold
	default:
		return false
	}
}

// Inverse is the condition that means "no longer breaching" -- used to
// derive the default recovery check when a rule has no explicit
// recovery_threshold (spec §10's hysteresis is then a zero-width gap:
// resolve exactly when the trigger condition itself stops holding).
func (c AlertCondition) Inverse() AlertCondition {
	switch c {
	case CondGreaterThan:
		return CondLessThanOrEqual
	case CondLessThan:
		return CondGreaterThanOrEqual
	case CondGreaterThanOrEqual:
		return CondLessThan
	case CondLessThanOrEqual:
		return CondGreaterThan
	default:
		return CondEqual
	}
}

// AlertSeverity mirrors HealthStatus's vocabulary at the three levels
// spec §4 actually asks for -- a distinct type, not reused HealthStatus
// directly, since HealthStatus also has UNKNOWN/OFFLINE which have no
// meaning for a configured alert rule's severity.
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "INFO"
	AlertSeverityWarning  AlertSeverity = "WARNING"
	AlertSeverityCritical AlertSeverity = "CRITICAL"
)

// AlertStatus is the alert lifecycle (spec §3).
type AlertStatus string

const (
	AlertStatusActive       AlertStatus = "ACTIVE"
	AlertStatusAcknowledged AlertStatus = "ACKNOWLEDGED"
	AlertStatusResolved     AlertStatus = "RESOLVED"
	AlertStatusSuppressed   AlertStatus = "SUPPRESSED"
)

// NotificationChannel is the closed set of delivery channels (spec §23).
// Only IN_APP and WEBHOOK have a registered NotificationProvider today;
// EMAIL/SLACK/TEAMS are valid values a policy can reference (so the
// schema and UI never need to change when a provider is added) but
// resolve to "no provider configured" until one is.
type NotificationChannel string

const (
	ChannelInApp   NotificationChannel = "IN_APP"
	ChannelEmail   NotificationChannel = "EMAIL"
	ChannelSlack   NotificationChannel = "SLACK"
	ChannelTeams   NotificationChannel = "TEAMS"
	ChannelWebhook NotificationChannel = "WEBHOOK"
)

// NotificationCategory groups notifications for the notification center
// (spec §21).
type NotificationCategory string

const (
	CategoryCriticalAlert NotificationCategory = "CRITICAL_ALERT"
	CategoryWarning       NotificationCategory = "WARNING"
	CategoryOperations    NotificationCategory = "OPERATIONS"
	CategoryDatabaseEvent NotificationCategory = "DATABASE_EVENT"
	CategoryVMEvent       NotificationCategory = "VM_EVENT"
	CategoryDockerEvent   NotificationCategory = "DOCKER_EVENT"
	CategorySystemEvent   NotificationCategory = "SYSTEM_EVENT"
)

// AlertTemplate is a predefined rule shape (spec §40) an Admin can start
// a new rule from -- sane defaults, not a hard requirement (every field
// remains editable).
type AlertTemplate struct {
	Type              AlertType
	Metric            AlertMetric
	Label             string
	DefaultCondition  AlertCondition
	DefaultThreshold  float64
	DefaultDuration   int32
	DefaultSeverity   AlertSeverity
	AppliesToResource string // "VM" | "DATABASE" | "OBJECT_STORAGE" | "DOCKER_CONTAINER" | "K8S_CLUSTER" | "K8S_POD" | "DOCKER_HOST" | "DOCKER_HOST_CONTAINER"
}

// AlertTemplates is the full catalog (spec §40/§39's worked examples).
var AlertTemplates = []AlertTemplate{
	{AlertTypeVMHighCPU, MetricCPUPercent, "VM CPU usage high", CondGreaterThan, 90, 300, AlertSeverityWarning, "VM"},
	{AlertTypeVMHighMemory, MetricMemoryPercent, "VM memory usage high", CondGreaterThan, 90, 300, AlertSeverityWarning, "VM"},
	{AlertTypeVMHighStorage, MetricStoragePercent, "VM storage usage high", CondGreaterThan, 90, 300, AlertSeverityWarning, "VM"},
	{AlertTypeVMUnavailable, MetricVMUnreachable, "VM unreachable", CondEqual, 1, 60, AlertSeverityCritical, "VM"},

	{AlertTypeDockerContainerStopped, MetricContainerStopped, "Container stopped unexpectedly", CondEqual, 1, 0, AlertSeverityWarning, "DOCKER_CONTAINER"},
	{AlertTypeDockerContainerRestarting, MetricContainerRestarting, "Container restarting", CondEqual, 1, 60, AlertSeverityWarning, "DOCKER_CONTAINER"},
	{AlertTypeDockerContainerUnhealthy, MetricContainerUnhealthy, "Container unhealthy", CondEqual, 1, 60, AlertSeverityWarning, "DOCKER_CONTAINER"},

	{AlertTypeDatabaseUnavailable, MetricDBUnreachable, "Database unavailable", CondEqual, 1, 60, AlertSeverityCritical, "DATABASE"},
	{AlertTypeDatabaseHighConnections, MetricDBConnectionPercent, "Database connection usage high", CondGreaterThan, 85, 300, AlertSeverityWarning, "DATABASE"},
	{AlertTypeDatabaseHighLatency, MetricDBLatencyP95Ms, "Database query latency high", CondGreaterThan, 1000, 300, AlertSeverityWarning, "DATABASE"},
	{AlertTypeDatabaseLockContention, MetricDBLocksBlocked, "Database lock contention", CondGreaterThanOrEqual, 3, 180, AlertSeverityWarning, "DATABASE"},
	{AlertTypeDatabaseReplicationLag, MetricDBReplicationLagSecs, "Database replication lag", CondGreaterThan, 10, 180, AlertSeverityWarning, "DATABASE"},
	{AlertTypeDatabaseHighStorage, MetricDBStorageBytes, "Database storage usage high", CondGreaterThan, 100, 300, AlertSeverityWarning, "DATABASE"}, // threshold in GB
	{AlertTypeDatabaseLowCacheHit, MetricDBCacheHitPercent, "Database cache hit ratio low", CondLessThan, 90, 300, AlertSeverityWarning, "DATABASE"},

	// Object storage (Step 17 Phase 3) -- default thresholds mirror the
	// OBJECT_STORAGE_GROWTH_WARNING_PERCENT/OBJECT_STORAGE_ERROR_RATE_WARNING_PERCENT
	// config defaults (config.go), same "template default, still fully
	// editable" convention as every other entry above. Public access and
	// encryption-disabled use duration=0 (alert immediately on the next
	// evaluation cycle, mirroring AlertTypeDockerContainerStopped's
	// immediate-trigger convention) -- these are binary security facts,
	// not a metric that needs a sustained-breach window to avoid a flapping
	// false positive.
	{AlertTypeObjectStorageUnavailable, MetricObjectStorageUnreachable, "Object storage unavailable", CondEqual, 1, 60, AlertSeverityCritical, "OBJECT_STORAGE"},
	{AlertTypeObjectStorageHighGrowth, MetricObjectStorageGrowthPercent, "Object storage growth high", CondGreaterThan, 20, 300, AlertSeverityWarning, "OBJECT_STORAGE"},
	{AlertTypeObjectStoragePublicAccess, MetricObjectStoragePublicAccessFlag, "Object storage bucket publicly accessible", CondEqual, 1, 0, AlertSeverityCritical, "OBJECT_STORAGE"},
	{AlertTypeObjectStorageEncryptionDisabled, MetricObjectStorageEncryptionDisabledFlag, "Object storage bucket encryption disabled", CondEqual, 1, 0, AlertSeverityWarning, "OBJECT_STORAGE"},
	{AlertTypeObjectStorageHighErrorRate, MetricObjectStorageErrorRatePercent, "Object storage error rate high", CondGreaterThan, 5, 300, AlertSeverityWarning, "OBJECT_STORAGE"},

	// Alert Rules widening (migration 058): Kubernetes clusters/pods,
	// standalone Docker Hosts, and log-based alerts. K8S_CLUSTER_UNAVAILABLE
	// and DOCKER_HOST_UNAVAILABLE mirror VM/Database/Object-Storage
	// "unavailable"'s own duration=60/Critical convention exactly. The
	// three *_HIGH_ERROR_LOGS types share one convention: >=5 ERROR/CRITICAL
	// lines within a 5-minute window is "high" -- a deliberately simple,
	// widely-applicable default (every field remains fully editable, same
	// as every template above).
	{AlertTypeK8sClusterUnavailable, MetricK8sClusterUnreachable, "Kubernetes cluster agent disconnected", CondEqual, 1, 60, AlertSeverityCritical, "K8S_CLUSTER"},

	{AlertTypeK8sPodNotRunning, MetricK8sPodUnavailable, "Pod not running", CondEqual, 1, 60, AlertSeverityCritical, "K8S_POD"},
	{AlertTypeK8sPodCrashLooping, MetricK8sPodRestartCount, "Pod restarting repeatedly (crash loop)", CondGreaterThanOrEqual, 5, 300, AlertSeverityWarning, "K8S_POD"},
	{AlertTypeK8sPodHighCPU, MetricK8sPodCPUMillicores, "Pod CPU usage high", CondGreaterThan, 900, 300, AlertSeverityWarning, "K8S_POD"},     // millicores
	{AlertTypeK8sPodHighMemory, MetricK8sPodMemoryBytes, "Pod memory usage high", CondGreaterThan, 512, 300, AlertSeverityWarning, "K8S_POD"}, // threshold in MB
	{AlertTypeK8sPodHighErrorLogs, MetricK8sPodLogErrorCount, "Pod logging errors frequently", CondGreaterThanOrEqual, 5, 300, AlertSeverityWarning, "K8S_POD"},

	{AlertTypeDockerHostUnavailable, MetricDockerHostUnreachable, "Docker Host agent disconnected", CondEqual, 1, 60, AlertSeverityCritical, "DOCKER_HOST"},
	{AlertTypeDockerHostContainerHighErrorLogs, MetricDockerHostContainerLogErrorCount, "Container logging errors frequently", CondGreaterThanOrEqual, 5, 300, AlertSeverityWarning, "DOCKER_HOST_CONTAINER"},

	{AlertTypeDockerContainerHighErrorLogs, MetricContainerLogErrorCount, "Container logging errors frequently", CondGreaterThanOrEqual, 5, 300, AlertSeverityWarning, "DOCKER_CONTAINER"},
}
