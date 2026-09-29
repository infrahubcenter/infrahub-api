package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// Fixed, backend-authored, read-only monitoring commands (Step 6 spec §9,
// §66-67). Machine-readable /proc interfaces are preferred over
// human-formatted tools wherever the kernel exposes one directly; `df`
// and `ps` are the two exceptions since there is no /proc equivalent.
// Exactly like discovery's commands (Step 5), these are never built from
// user input and there is no arbitrary-execution path anywhere near them.
const (
	cmdMonProcStat = "cat /proc/stat"
	cmdMonMemInfo  = "cat /proc/meminfo"
	cmdMonLoadAvg  = "cat /proc/loadavg"
	cmdMonUptime   = "cat /proc/uptime"
	// -P: POSIX portable output (one line per filesystem, no wrapping
	// unless a device name is unusually long -- handled in ParseDF). -k:
	// 1024-byte blocks. -T: filesystem type column, needed to filter
	// pseudo filesystems without an allowlist (spec §19).
	cmdMonDF     = "df -PkT"
	cmdMonNetDev = "cat /proc/net/dev"
	// `=` suppresses the header on the STAT column alone -- ParsePS reads
	// one state code per line, nothing else.
	cmdMonPS = "ps -eo stat="
)

// cpuJiffiesSnapshot is CPUStat's JSON-on-disk form (monitoring_snapshots
// .cpu_raw_jiffies) -- see the migration's comment on that column for why
// this is one JSON blob rather than 8 bigint columns.
type cpuJiffiesSnapshot struct {
	User, Nice, System, Idle, IOWait, IRQ, SoftIRQ, Steal int64
}

func toCPUJiffiesSnapshot(s CPUStat) cpuJiffiesSnapshot {
	return cpuJiffiesSnapshot{
		User: s.User, Nice: s.Nice, System: s.System, Idle: s.Idle,
		IOWait: s.IOWait, IRQ: s.IRQ, SoftIRQ: s.SoftIRQ, Steal: s.Steal,
	}
}

func (j cpuJiffiesSnapshot) toCPUStat() CPUStat {
	return CPUStat{
		User: j.User, Nice: j.Nice, System: j.System, Idle: j.Idle,
		IOWait: j.IOWait, IRQ: j.IRQ, SoftIRQ: j.SoftIRQ, Steal: j.Steal,
	}
}

// MonitoringResult is one collection cycle's outcome -- mirrors
// DiscoveryResult's shape/philosophy (Step 5): always returned even on
// total failure, error is non-nil only when collection couldn't even be
// attempted or a database write failed.
type MonitoringResult struct {
	Status       string // SUCCESS | PARTIAL | FAILED
	ErrorSummary string
	Health       HealthStatus
}

// VMMonitoringService orchestrates one monitoring cycle: connect once via
// SSHService (reusing the exact same credential/host-key machinery as
// Step 5 -- spec §8/§66 forbid a second SSH implementation), run each
// fixed metric command through RemoteExecutor, parse with the functions
// in monitoring_parse.go, and persist only what actually succeeded.
type VMMonitoringService struct {
	store          *repository.Store
	ssh            *SSHService
	executor       *RemoteExecutor
	commandTimeout time.Duration
	thresholds     HealthThresholds
}

// NewVMMonitoringService creates a VMMonitoringService.
func NewVMMonitoringService(store *repository.Store, ssh *SSHService, executor *RemoteExecutor, commandTimeout time.Duration, thresholds HealthThresholds) *VMMonitoringService {
	return &VMMonitoringService{store: store, ssh: ssh, executor: executor, commandTimeout: commandTimeout, thresholds: thresholds}
}

// Collect runs one full monitoring cycle for resourceID. Like
// VMDiscoveryService.Discover, a failed/partial SSH-level outcome is
// represented in MonitoringResult.Status, not as a Go error -- it's an
// expected, handled outcome the scheduler must be able to log and move on
// from without treating it as exceptional.
func (s *VMMonitoringService) Collect(ctx context.Context, resourceID uuid.UUID) (MonitoringResult, error) {
	vm, err := s.store.GetVMByResourceID(ctx, resourceID)
	if err != nil {
		return MonitoringResult{}, fmt.Errorf("load vm: %w", err)
	}

	run, err := s.store.CreateMonitoringRun(ctx, vm.ID)
	if err != nil {
		return MonitoringResult{}, fmt.Errorf("create monitoring run: %w", err)
	}

	client, connErr := s.ssh.Connect(ctx, resourceID)
	// Step 6 spec §33: a connection failure must update connection/resource
	// status exactly like a failed discovery or connection test does --
	// reusing RecordConnectionOutcome keeps that mapping in one place
	// rather than reimplementing it here.
	if outcomeErr := RecordConnectionOutcome(ctx, s.store, resourceID, vm.ID, connErr); outcomeErr != nil {
		return MonitoringResult{}, fmt.Errorf("record connection outcome: %w", outcomeErr)
	}
	if connErr != nil {
		sshErr := classifyConnectError(connErr)
		if _, err := s.store.CompleteMonitoringRun(ctx, generated.CompleteMonitoringRunParams{
			ID: run.ID, Status: "FAILED", ErrorSummary: pgutil.Text(sshErr.Message),
		}); err != nil {
			return MonitoringResult{}, fmt.Errorf("complete monitoring run: %w", err)
		}
		// No snapshot is written on a connection failure (spec §33: "do not
		// delete previous metric history... keep last successful
		// monitoring snapshot"). Health for display purposes is derived
		// from connection state at read time -- see DeriveDisplayHealth.
		return MonitoringResult{Status: "FAILED", ErrorSummary: "Connection failed: " + sshErr.Message, Health: HealthOffline}, nil
	}
	defer client.Close()

	// One previous-snapshot read serves both CPU-delta math (needs exactly
	// the most recent sample) and the 3-sample anti-flap window
	// cpuDimensionStatus checks (spec §23) -- fetched once up front, per
	// spec §65's "avoid one SSH connection/one query per metric" spirit
	// applied to the database side too.
	recent, err := s.store.ListRecentMonitoringSnapshots(ctx, generated.ListRecentMonitoringSnapshotsParams{ResourceID: resourceID, Limit: 3})
	if err != nil {
		return MonitoringResult{}, fmt.Errorf("load recent snapshots: %w", err)
	}

	type field struct {
		name      string
		succeeded bool
	}
	var fields []field
	ok := func(name string, succeeded bool) {
		fields = append(fields, field{name: name, succeeded: succeeded})
	}

	insert := generated.InsertMonitoringSnapshotParams{ResourceID: resourceID}

	// --- CPU (and core count, from the same read -- see CountCPUCores) ---
	var currentCPU CPUStat
	haveCPU := false
	if res, err := s.executor.Execute(ctx, client, cmdMonProcStat, s.commandTimeout); err == nil && res.ExitCode == 0 {
		if stat, parsed := ParseProcStat(res.Stdout); parsed {
			currentCPU = stat
			haveCPU = true
			raw, _ := json.Marshal(toCPUJiffiesSnapshot(stat))
			insert.CpuRawJiffies = pgutil.Text(string(raw))
			if cores := CountCPUCores(res.Stdout); cores > 0 {
				insert.CpuCores = pgutil.Int4(cores)
			} else if fallback := pgutil.Int4Ptr(vm.CpuCores); fallback != nil {
				insert.CpuCores = pgutil.Int4(*fallback)
			}
		}
	}
	ok("cpu", haveCPU)

	// --- Memory ---
	haveMemory := false
	var memMetrics MemoryMetrics
	if res, err := s.executor.Execute(ctx, client, cmdMonMemInfo, s.commandTimeout); err == nil && res.ExitCode == 0 {
		if m, parsed := ParseMemInfo(res.Stdout); parsed {
			memMetrics = m
			haveMemory = true
			insert.MemoryUsedBytes = pgutil.Int8(m.UsedBytes)
			insert.MemoryTotalBytes = pgutil.Int8(m.TotalBytes)
			if m.HasSwap {
				insert.SwapUsedBytes = pgutil.Int8(m.SwapUsedBytes)
				insert.SwapTotalBytes = pgutil.Int8(m.SwapTotalBytes)
			}
		}
	}
	ok("memory", haveMemory)

	// --- Load average ---
	haveLoad := false
	if res, err := s.executor.Execute(ctx, client, cmdMonLoadAvg, s.commandTimeout); err == nil && res.ExitCode == 0 {
		if one, five, fifteen, parsed := ParseLoadAvg(res.Stdout); parsed {
			haveLoad = true
			insert.Load1m = pgutil.Float8(one)
			insert.Load5m = pgutil.Float8(five)
			insert.Load15m = pgutil.Float8(fifteen)
		}
	}
	ok("load", haveLoad)

	// --- Uptime ---
	haveUptime := false
	if res, err := s.executor.Execute(ctx, client, cmdMonUptime, s.commandTimeout); err == nil && res.ExitCode == 0 {
		if seconds, parsed := ParseUptime(res.Stdout); parsed {
			haveUptime = true
			insert.UptimeSeconds = pgutil.Int8(seconds)
		}
	}
	ok("uptime", haveUptime)

	// --- Filesystems ---
	haveFilesystem := false
	var rootUsagePercent *float64
	var filesystems []FilesystemEntry
	if res, err := s.executor.Execute(ctx, client, cmdMonDF, s.commandTimeout); err == nil && res.ExitCode == 0 {
		entries := FilterFilesystems(ParseDF(res.Stdout))
		if len(entries) > 0 {
			haveFilesystem = true
			filesystems = entries
			for _, e := range entries {
				if e.MountPoint == "/" {
					pct := e.UsagePercent
					rootUsagePercent = &pct
					insert.StorageUsedBytes = pgutil.Int8(e.UsedBytes)
					insert.StorageTotalBytes = pgutil.Int8(e.TotalBytes)
				}
			}
		}
	}
	ok("filesystem", haveFilesystem)

	// --- Network ---
	// Rates are computed here, against each interface's previous row, all
	// BEFORE anything for this cycle is written -- so "previous" never
	// risks resolving to the row this same cycle is about to insert.
	haveNetwork := false
	var networkSamples []NetworkInterfaceSample
	networkRates := make(map[string]NetworkRate) // interface name -> rate, only present when computable
	now := time.Now()
	if res, err := s.executor.Execute(ctx, client, cmdMonNetDev, s.commandTimeout); err == nil && res.ExitCode == 0 {
		samples := ParseNetDev(res.Stdout)
		haveNetwork = true // an empty (no non-lo interfaces) result is still a valid read, not a failure
		networkSamples = samples
		var totalRxBytes, totalTxBytes int64
		var totalRxRate, totalTxRate float64
		anyRate := false
		for _, sample := range samples {
			totalRxBytes += sample.RxBytes
			totalTxBytes += sample.TxBytes

			prev, prevErr := s.store.GetPreviousVMNetworkSnapshot(ctx, generated.GetPreviousVMNetworkSnapshotParams{
				VmID: vm.ID, InterfaceName: sample.Name,
			})
			if prevErr != nil {
				continue // first sample for this interface: no rate yet (spec §25)
			}
			elapsed := now.Sub(prev.CapturedAt.Time).Seconds()
			prevSample := NetworkInterfaceSample{Name: sample.Name, RxBytes: prev.RxBytes, TxBytes: prev.TxBytes}
			if rate, computed := ComputeNetworkRate(prevSample, sample, elapsed); computed {
				networkRates[sample.Name] = rate
				totalRxRate += rate.RxBytesPerSec
				totalTxRate += rate.TxBytesPerSec
				anyRate = true
			}
		}
		insert.NetworkRxBytes = pgutil.Int8(totalRxBytes)
		insert.NetworkTxBytes = pgutil.Int8(totalTxBytes)
		if anyRate {
			insert.NetworkRxRateBytes = pgutil.Int8(int64(totalRxRate))
			insert.NetworkTxRateBytes = pgutil.Int8(int64(totalTxRate))
		}
	}
	ok("network", haveNetwork)

	// --- Process summary ---
	haveProcess := false
	if res, err := s.executor.Execute(ctx, client, cmdMonPS, s.commandTimeout); err == nil && res.ExitCode == 0 {
		if summary, parsed := ParsePS(res.Stdout); parsed {
			haveProcess = true
			insert.ProcessCount = pgutil.Int4(int32(summary.Total))
			insert.ProcessRunningCount = pgutil.Int4(int32(summary.Running))
			insert.ProcessSleepingCount = pgutil.Int4(int32(summary.Sleeping))
			insert.ProcessZombieCount = pgutil.Int4(int32(summary.Zombie))
		}
	}
	ok("process", haveProcess)

	// --- CPU percentage: only ever computed as a delta (spec §10-12) ---
	var cpuUsagePercent *float64
	if haveCPU && len(recent) > 0 {
		if prevRaw := pgutil.TextOrEmpty(recent[0].CpuRawJiffies); prevRaw != "" {
			var prevJiffies cpuJiffiesSnapshot
			if jsonErr := json.Unmarshal([]byte(prevRaw), &prevJiffies); jsonErr == nil {
				if usage, computed := ComputeCPUUsage(prevJiffies.toCPUStat(), currentCPU); computed {
					cpuUsagePercent = &usage.UsagePercent
					insert.CpuUsagePercent = pgutil.Float8(usage.UsagePercent)
					insert.CpuUserPercent = pgutil.Float8(usage.UserPercent)
					insert.CpuSystemPercent = pgutil.Float8(usage.SystemPercent)
					insert.CpuIowaitPercent = pgutil.Float8(usage.IOWaitPercent)
					insert.CpuIdlePercent = pgutil.Float8(usage.IdlePercent)
				}
			}
		}
	}
	// A first sample (or one where the delta wasn't usable) intentionally
	// leaves cpu_usage_percent/etc as SQL NULL -- spec §12 forbids
	// fabricating a value here.

	// --- Health: computed once per cycle from what was actually collected ---
	cpuHistory := make([]float64, 0, 4)
	if cpuUsagePercent != nil {
		cpuHistory = append(cpuHistory, *cpuUsagePercent)
	}
	for _, r := range recent {
		if v := pgutil.Float8Ptr(r.CpuUsagePercent); v != nil {
			cpuHistory = append(cpuHistory, *v)
		}
	}
	var memoryPercent *float64
	if haveMemory {
		p := memMetrics.UsagePercent
		memoryPercent = &p
	}
	health := ComputeSnapshotHealth(cpuUsagePercent, memoryPercent, rootUsagePercent, cpuHistory, s.thresholds)
	insert.Status = pgutil.Text(string(health))

	// --- Persist: snapshot, then filesystem/network detail rows ---
	// Not a single database transaction across all four writes: the
	// dominant failure mode here is a bad row (a NULL where NOT NULL is
	// required, a stray constraint) on one filesystem/interface, not a
	// mid-write crash, and Step 6 spec §32/§70 explicitly wants a
	// partially-successful cycle to keep whatever it did manage to write
	// rather than roll everything back over one bad row.
	if _, err := s.store.InsertMonitoringSnapshot(ctx, insert); err != nil {
		return MonitoringResult{}, fmt.Errorf("insert monitoring snapshot: %w", err)
	}

	if haveFilesystem {
		for _, e := range filesystems {
			if _, err := s.store.InsertVMFilesystemSnapshot(ctx, generated.InsertVMFilesystemSnapshotParams{
				VmID: vm.ID, MountPoint: e.MountPoint, Filesystem: pgutil.Text(e.Filesystem),
				TotalBytes: pgutil.Int8(e.TotalBytes), UsedBytes: pgutil.Int8(e.UsedBytes),
				AvailableBytes: pgutil.Int8(e.AvailableBytes), UsagePercent: pgutil.Float8(e.UsagePercent),
			}); err != nil {
				// A single filesystem row failing to insert doesn't
				// invalidate everything else already captured this cycle.
				haveFilesystem = false
			}
		}
	}

	if haveNetwork {
		for _, sample := range networkSamples {
			params := generated.InsertVMNetworkSnapshotParams{
				VmID: vm.ID, InterfaceName: sample.Name,
				RxBytes: sample.RxBytes, TxBytes: sample.TxBytes,
				RxPackets: sample.RxPackets, TxPackets: sample.TxPackets,
				RxErrors: sample.RxErrors, TxErrors: sample.TxErrors,
				RxDropped: sample.RxDropped, TxDropped: sample.TxDropped,
			}
			if rate, ok := networkRates[sample.Name]; ok {
				params.RxRateBytes = pgutil.Int8(int64(rate.RxBytesPerSec))
				params.TxRateBytes = pgutil.Int8(int64(rate.TxBytesPerSec))
			}
			if _, err := s.store.InsertVMNetworkSnapshot(ctx, params); err != nil {
				haveNetwork = false
			}
		}
	}

	succeeded, total := 0, len(fields)
	var failedNames []string
	for _, f := range fields {
		if f.succeeded {
			succeeded++
		} else {
			failedNames = append(failedNames, f.name)
		}
	}

	var status, errorSummary string
	switch {
	case succeeded == total:
		status = "SUCCESS"
	case succeeded == 0:
		status = "FAILED"
		errorSummary = "Connection succeeded, but no metrics could be collected."
	default:
		status = "PARTIAL"
		errorSummary = "Connection succeeded, but some metrics could not be collected: " + joinNames(failedNames)
	}

	if _, err := s.store.CompleteMonitoringRun(ctx, generated.CompleteMonitoringRunParams{
		ID: run.ID, Status: status, ErrorSummary: pgutil.Text(errorSummary),
	}); err != nil {
		return MonitoringResult{}, fmt.Errorf("complete monitoring run: %w", err)
	}

	return MonitoringResult{Status: status, ErrorSummary: errorSummary, Health: health}, nil
}

func joinNames(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}
