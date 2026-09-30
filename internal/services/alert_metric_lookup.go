package services

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// alertLogScanCap bounds how many of a target's most recent log lines a
// *_HIGH_ERROR_LOGS rule scans per evaluation cycle -- mirrors
// handlers.logSeverityScanCap's own reasoning (a heuristic, bounded scan,
// never an exact aggregate over unlimited history), kept as a separate
// constant since services can't import handlers.
const alertLogScanCap = 5000

// metricSample is one resolved (value, available) pair -- available is
// false when nothing has ever been collected yet, which the engine
// treats as "cannot evaluate this cycle," never as a fabricated 0 (spec's
// "never fabricate a metric" precedent from Step 12/13 monitoring).
type metricSample struct {
	Value     float64
	Available bool
}

// alertMetricLookup resolves AlertMetric values from the exact same
// tables Steps 6/8/13 already populate -- monitoring_snapshots (VM),
// docker_container_metric_snapshots/docker_containers (Docker, mostly
// already present on the evaluation row itself), standalone_database_metrics/
// standalone_database_deep_metrics (Database). It never collects a new
// sample itself; it only reads the latest one an existing scheduler
// already wrote, and caches one snapshot per resource per evaluation
// cycle so N rules on the same resource cost one query, not N (spec
// §51's "efficient metric lookup").
type alertMetricLookup struct {
	store          *repository.Store
	dockerAgentHub *DockerAgentHub
	k8sAgentHub    *K8sAgentHub

	vmSnapshots map[uuid.UUID]*generated.MonitoringSnapshot
	dbMetrics   map[uuid.UUID]*generated.StandaloneDatabaseMetric
	dbDeep      map[uuid.UUID]*generated.StandaloneDatabaseDeepMetric
	osRecords   map[uuid.UUID]*generated.ObjectStorage
	osDeep      map[uuid.UUID]*generated.ObjectStorageDeepMetric
}

func newAlertMetricLookup(store *repository.Store, dockerAgentHub *DockerAgentHub, k8sAgentHub *K8sAgentHub) *alertMetricLookup {
	return &alertMetricLookup{
		store:          store,
		dockerAgentHub: dockerAgentHub,
		k8sAgentHub:    k8sAgentHub,
		vmSnapshots:    map[uuid.UUID]*generated.MonitoringSnapshot{},
		dbMetrics:      map[uuid.UUID]*generated.StandaloneDatabaseMetric{},
		dbDeep:         map[uuid.UUID]*generated.StandaloneDatabaseDeepMetric{},
		osRecords:      map[uuid.UUID]*generated.ObjectStorage{},
		osDeep:         map[uuid.UUID]*generated.ObjectStorageDeepMetric{},
	}
}

// vmAgentSampleMaxAge bounds how old a VM Agent sample may be and still
// drive a VM alert (the agent pushes every ~15s) -- so a disconnected
// agent's last reading can't keep a threshold "breached" indefinitely.
const vmAgentSampleMaxAge = 2 * time.Minute

// vmSnapshot returns the VM's latest metrics from whichever source is
// newer: the SSH monitor's monitoring_snapshots, or the VM Agent's
// vm_agent_metric_snapshots. Agent-only VMs (Host Metrics & Logs) never
// have SSH snapshots at all, so without the agent source their CPU/memory/
// storage alert rules could never evaluate.
func (l *alertMetricLookup) vmSnapshot(ctx context.Context, resourceID uuid.UUID, vmID pgtype.UUID) *generated.MonitoringSnapshot {
	if snap, ok := l.vmSnapshots[resourceID]; ok {
		return snap
	}
	var best *generated.MonitoringSnapshot
	if snap, err := l.store.GetLatestMonitoringSnapshot(ctx, resourceID); err == nil {
		best = &snap
	}
	if vmID.Valid {
		if a, err := l.store.GetLatestVMAgentMetricSnapshot(ctx, uuid.UUID(vmID.Bytes)); err == nil &&
			a.CapturedAt.Valid && time.Since(a.CapturedAt.Time) <= vmAgentSampleMaxAge &&
			(best == nil || !best.CapturedAt.Valid || a.CapturedAt.Time.After(best.CapturedAt.Time)) {
			best = &generated.MonitoringSnapshot{
				ResourceID:        resourceID,
				CapturedAt:        a.CapturedAt,
				CpuUsagePercent:   a.CpuPercent,
				MemoryUsedBytes:   a.MemoryUsedBytes,
				MemoryTotalBytes:  a.MemoryTotalBytes,
				StorageUsedBytes:  a.StorageUsedBytes,
				StorageTotalBytes: a.StorageTotalBytes,
			}
		}
	}
	l.vmSnapshots[resourceID] = best
	return best
}

func (l *alertMetricLookup) dbMetric(ctx context.Context, databaseID uuid.UUID) *generated.StandaloneDatabaseMetric {
	if m, ok := l.dbMetrics[databaseID]; ok {
		return m
	}
	m, err := l.store.GetLatestStandaloneDatabaseMetric(ctx, databaseID)
	if err != nil {
		l.dbMetrics[databaseID] = nil
		return nil
	}
	l.dbMetrics[databaseID] = &m
	return &m
}

func (l *alertMetricLookup) dbDeepMetric(ctx context.Context, databaseID uuid.UUID) *generated.StandaloneDatabaseDeepMetric {
	if m, ok := l.dbDeep[databaseID]; ok {
		return m
	}
	m, err := l.store.GetLatestStandaloneDatabaseDeepMetric(ctx, databaseID)
	if err != nil {
		l.dbDeep[databaseID] = nil
		return nil
	}
	l.dbDeep[databaseID] = &m
	return &m
}

func (l *alertMetricLookup) objectStorage(ctx context.Context, objectStorageID uuid.UUID) *generated.ObjectStorage {
	if os, ok := l.osRecords[objectStorageID]; ok {
		return os
	}
	os, err := l.store.GetObjectStorageByID(ctx, objectStorageID)
	if err != nil {
		l.osRecords[objectStorageID] = nil
		return nil
	}
	l.osRecords[objectStorageID] = &os
	return &os
}

func (l *alertMetricLookup) objectStorageDeepMetric(ctx context.Context, objectStorageID uuid.UUID) *generated.ObjectStorageDeepMetric {
	if m, ok := l.osDeep[objectStorageID]; ok {
		return m
	}
	m, err := l.store.GetLatestObjectStorageDeepMetric(ctx, objectStorageID)
	if err != nil {
		l.osDeep[objectStorageID] = nil
		return nil
	}
	l.osDeep[objectStorageID] = &m
	return &m
}

// Resolve returns the current value for rule's metric, given the
// evaluation row's already-joined resource context.
func (l *alertMetricLookup) Resolve(ctx context.Context, row generated.ListEnabledAlertRulesForEvaluationRow) metricSample {
	switch AlertMetric(row.Metric) {
	case MetricCPUPercent:
		if !row.VmID.Valid {
			return metricSample{}
		}
		snap := l.vmSnapshot(ctx, row.ResourceID, row.VmID)
		if snap == nil || !snap.CpuUsagePercent.Valid {
			return metricSample{}
		}
		return metricSample{Value: snap.CpuUsagePercent.Float64, Available: true}

	case MetricMemoryPercent:
		if !row.VmID.Valid {
			return metricSample{}
		}
		snap := l.vmSnapshot(ctx, row.ResourceID, row.VmID)
		if snap == nil || !snap.MemoryUsedBytes.Valid || !snap.MemoryTotalBytes.Valid || snap.MemoryTotalBytes.Int64 == 0 {
			return metricSample{}
		}
		pct := float64(snap.MemoryUsedBytes.Int64) / float64(snap.MemoryTotalBytes.Int64) * 100
		return metricSample{Value: pct, Available: true}

	case MetricStoragePercent:
		if !row.VmID.Valid {
			return metricSample{}
		}
		snap := l.vmSnapshot(ctx, row.ResourceID, row.VmID)
		if snap == nil || !snap.StorageUsedBytes.Valid || !snap.StorageTotalBytes.Valid || snap.StorageTotalBytes.Int64 == 0 {
			return metricSample{}
		}
		pct := float64(snap.StorageUsedBytes.Int64) / float64(snap.StorageTotalBytes.Int64) * 100
		return metricSample{Value: pct, Available: true}

	case MetricVMUnreachable:
		if !row.VmID.Valid {
			return metricSample{}
		}
		vm, err := l.store.GetVMByID(ctx, uuid.UUID(row.VmID.Bytes))
		if err != nil {
			return metricSample{}
		}
		if vm.ConnectionStatus == "CONNECTED" {
			return metricSample{Value: 0, Available: true}
		}
		return metricSample{Value: 1, Available: true}

	case MetricContainerStopped:
		if !row.ContainerStatus.Valid {
			return metricSample{}
		}
		if row.ContainerStatus.String == "EXITED" || row.ContainerStatus.String == "DEAD" {
			return metricSample{Value: 1, Available: true}
		}
		return metricSample{Value: 0, Available: true}

	case MetricContainerRestarting:
		if !row.ContainerStatus.Valid {
			return metricSample{}
		}
		if row.ContainerStatus.String == "RESTARTING" {
			return metricSample{Value: 1, Available: true}
		}
		return metricSample{Value: 0, Available: true}

	case MetricContainerUnhealthy:
		if !row.ContainerHealth.Valid {
			return metricSample{}
		}
		if row.ContainerHealth.String == "UNHEALTHY" {
			return metricSample{Value: 1, Available: true}
		}
		return metricSample{Value: 0, Available: true}

	case MetricContainerRestartCount:
		if !row.ContainerRestartCount.Valid {
			return metricSample{}
		}
		return metricSample{Value: float64(row.ContainerRestartCount.Int32), Available: true}

	case MetricDBUnreachable:
		if !row.DatabaseID.Valid {
			return metricSample{}
		}
		db, err := l.store.GetDatabaseByID(ctx, uuid.UUID(row.DatabaseID.Bytes))
		if err != nil {
			return metricSample{}
		}
		if db.ConnectionStatus == "CONNECTED" {
			return metricSample{Value: 0, Available: true}
		}
		return metricSample{Value: 1, Available: true}

	case MetricDBConnectionPercent:
		if !row.DatabaseID.Valid {
			return metricSample{}
		}
		m := l.dbMetric(ctx, uuid.UUID(row.DatabaseID.Bytes))
		if m == nil || !m.Connections.Valid || !m.MaxConnections.Valid || m.MaxConnections.Int32 == 0 {
			return metricSample{}
		}
		pct := float64(m.Connections.Int32) / float64(m.MaxConnections.Int32) * 100
		return metricSample{Value: pct, Available: true}

	case MetricDBStorageBytes:
		if !row.DatabaseID.Valid {
			return metricSample{}
		}
		m := l.dbMetric(ctx, uuid.UUID(row.DatabaseID.Bytes))
		if m == nil || !m.DatabaseSizeBytes.Valid {
			return metricSample{}
		}
		gb := float64(m.DatabaseSizeBytes.Int64) / 1_000_000_000
		return metricSample{Value: gb, Available: true}

	case MetricDBLatencyP95Ms:
		if !row.DatabaseID.Valid {
			return metricSample{}
		}
		m := l.dbDeepMetric(ctx, uuid.UUID(row.DatabaseID.Bytes))
		if m == nil || !m.LatencyP95Ms.Valid {
			return metricSample{}
		}
		return metricSample{Value: m.LatencyP95Ms.Float64, Available: true}

	case MetricDBLocksBlocked:
		if !row.DatabaseID.Valid {
			return metricSample{}
		}
		m := l.dbDeepMetric(ctx, uuid.UUID(row.DatabaseID.Bytes))
		if m == nil || !m.LocksBlocked.Valid {
			return metricSample{}
		}
		return metricSample{Value: float64(m.LocksBlocked.Int32), Available: true}

	case MetricDBReplicationLagSecs:
		if !row.DatabaseID.Valid {
			return metricSample{}
		}
		m := l.dbDeepMetric(ctx, uuid.UUID(row.DatabaseID.Bytes))
		if m == nil || !m.ReplicationLagSeconds.Valid {
			return metricSample{}
		}
		return metricSample{Value: m.ReplicationLagSeconds.Float64, Available: true}

	case MetricDBCacheHitPercent:
		if !row.DatabaseID.Valid {
			return metricSample{}
		}
		m := l.dbDeepMetric(ctx, uuid.UUID(row.DatabaseID.Bytes))
		if m == nil || !m.CacheHitRatio.Valid {
			return metricSample{}
		}
		return metricSample{Value: m.CacheHitRatio.Float64, Available: true}

	case MetricObjectStorageUnreachable:
		if !row.ObjectStorageID.Valid {
			return metricSample{}
		}
		os := l.objectStorage(ctx, uuid.UUID(row.ObjectStorageID.Bytes))
		if os == nil {
			return metricSample{}
		}
		if os.ConnectionStatus == "CONNECTED" {
			return metricSample{Value: 0, Available: true}
		}
		return metricSample{Value: 1, Available: true}

	case MetricObjectStorageGrowthPercent:
		if !row.ObjectStorageID.Valid {
			return metricSample{}
		}
		m := l.objectStorageDeepMetric(ctx, uuid.UUID(row.ObjectStorageID.Bytes))
		if m == nil || !m.GrowthPercent.Valid {
			return metricSample{}
		}
		return metricSample{Value: m.GrowthPercent.Float64, Available: true}

	case MetricObjectStoragePublicAccessFlag:
		if !row.ObjectStorageID.Valid {
			return metricSample{}
		}
		os := l.objectStorage(ctx, uuid.UUID(row.ObjectStorageID.Bytes))
		if os == nil {
			return metricSample{}
		}
		switch os.PublicAccess {
		case "PUBLIC":
			return metricSample{Value: 1, Available: true}
		case "PRIVATE":
			return metricSample{Value: 0, Available: true}
		default: // UNKNOWN -- never fabricate a public/private verdict from absent evidence.
			return metricSample{}
		}

	case MetricObjectStorageEncryptionDisabledFlag:
		if !row.ObjectStorageID.Valid {
			return metricSample{}
		}
		os := l.objectStorage(ctx, uuid.UUID(row.ObjectStorageID.Bytes))
		if os == nil {
			return metricSample{}
		}
		switch os.EncryptionStatus {
		case "DISABLED":
			return metricSample{Value: 1, Available: true}
		case "ENABLED":
			return metricSample{Value: 0, Available: true}
		default: // UNKNOWN
			return metricSample{}
		}

	case MetricObjectStorageErrorRatePercent:
		if !row.ObjectStorageID.Valid {
			return metricSample{}
		}
		m := l.objectStorageDeepMetric(ctx, uuid.UUID(row.ObjectStorageID.Bytes))
		if m == nil || !m.ErrorRatePercent.Valid {
			return metricSample{}
		}
		return metricSample{Value: m.ErrorRatePercent.Float64, Available: true}

	case MetricK8sClusterUnreachable:
		if row.ResourceType != "K8S_CLUSTER" || l.k8sAgentHub == nil {
			return metricSample{}
		}
		if l.k8sAgentHub.IsConnected(row.ResourceID) {
			return metricSample{Value: 0, Available: true}
		}
		return metricSample{Value: 1, Available: true}

	case MetricDockerHostUnreachable:
		if row.ResourceType != "DOCKER_HOST" || l.dockerAgentHub == nil {
			return metricSample{}
		}
		if l.dockerAgentHub.IsConnected(row.ResourceID) {
			return metricSample{Value: 0, Available: true}
		}
		return metricSample{Value: 1, Available: true}

	case MetricK8sPodUnavailable:
		if !row.K8sPodID.Valid || !row.K8sPodPhase.Valid {
			return metricSample{}
		}
		if row.K8sPodPhase.String == "RUNNING" {
			return metricSample{Value: 0, Available: true}
		}
		return metricSample{Value: 1, Available: true}

	case MetricK8sPodRestartCount:
		if !row.K8sPodID.Valid || !row.K8sPodRestartCount.Valid {
			return metricSample{}
		}
		return metricSample{Value: float64(row.K8sPodRestartCount.Int32), Available: true}

	case MetricK8sPodCPUMillicores:
		if !row.K8sPodID.Valid || !row.K8sPodCpuUsageMillicores.Valid {
			return metricSample{}
		}
		return metricSample{Value: float64(row.K8sPodCpuUsageMillicores.Int64), Available: true}

	case MetricK8sPodMemoryBytes:
		if !row.K8sPodID.Valid || !row.K8sPodMemoryUsageBytes.Valid {
			return metricSample{}
		}
		mb := float64(row.K8sPodMemoryUsageBytes.Int64) / 1_000_000
		return metricSample{Value: mb, Available: true}

	case MetricContainerLogErrorCount:
		if !row.ContainerID.Valid {
			return metricSample{}
		}
		lines, err := l.store.ListDockerContainerLogLinesSince(ctx, generated.ListDockerContainerLogLinesSinceParams{
			DockerContainerID: uuid.UUID(row.ContainerID.Bytes),
			LoggedAt:          pgutil.Timestamptz(time.Now().Add(-time.Duration(row.DurationSeconds) * time.Second)),
			Limit:             alertLogScanCap,
		})
		if err != nil {
			return metricSample{}
		}
		return metricSample{Value: float64(alertLogErrorCount(lines)), Available: true}

	case MetricDockerHostContainerLogErrorCount:
		if !row.DockerHostContainerSightingID.Valid {
			return metricSample{}
		}
		lines, err := l.store.ListDockerHostContainerLogLinesSince(ctx, generated.ListDockerHostContainerLogLinesSinceParams{
			DockerHostContainerSightingID: uuid.UUID(row.DockerHostContainerSightingID.Bytes),
			LoggedAt:                      pgutil.Timestamptz(time.Now().Add(-time.Duration(row.DurationSeconds) * time.Second)),
			Limit:                         alertLogScanCap,
		})
		if err != nil {
			return metricSample{}
		}
		return metricSample{Value: float64(alertLogErrorCount(lines)), Available: true}

	case MetricK8sPodLogErrorCount:
		if !row.K8sPodID.Valid {
			return metricSample{}
		}
		lines, err := l.store.ListK8sPodLogLinesSince(ctx, generated.ListK8sPodLogLinesSinceParams{
			K8sPodID: uuid.UUID(row.K8sPodID.Bytes),
			LoggedAt: pgutil.Timestamptz(time.Now().Add(-time.Duration(row.DurationSeconds) * time.Second)),
			Limit:    alertLogScanCap,
		})
		if err != nil {
			return metricSample{}
		}
		return metricSample{Value: float64(alertLogErrorCount(lines)), Available: true}

	default:
		return metricSample{}
	}
}

// alertLogErrorCount classifies each line (services.ClassifyLogLine, the
// same read-time classification search/summary already use -- severity
// is never a stored column) and counts ERROR+CRITICAL -- the "current
// value" every *_HIGH_ERROR_LOGS rule compares against its threshold.
func alertLogErrorCount(lines []string) int {
	count := 0
	for _, line := range lines {
		switch ClassifyLogLine(line).Severity {
		case LogSeverityError, LogSeverityCritical:
			count++
		}
	}
	return count
}
