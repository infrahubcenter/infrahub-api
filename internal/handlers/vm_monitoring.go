package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// Step 6 spec §38: a bounded default/maximum on the history endpoint's
// time range and row count, so a client can never pull unlimited history
// in one request.
const (
	defaultHistoryRange = 24 * time.Hour
	maxHistoryRange     = 30 * 24 * time.Hour
	defaultHistoryLimit = 500
	maxHistoryLimit     = 2000
)

// MonitoringHandler implements the read-only monitoring API (current
// metrics, history) and the admin-only manual-collection trigger. Every
// endpoint checks VM authorization individually (Step 6 spec §40) -- a
// member never learns anything about a VM they aren't already authorized
// to view via GET /api/vms/:id, following the same 404-not-403 policy as
// every other VM-scoped endpoint in this project.
type MonitoringHandler struct {
	store      *repository.Store
	authz      *services.AuthorizationService
	scheduler  *services.MonitoringScheduler
	audit      *services.AuditService
	staleAfter time.Duration
}

// NewMonitoringHandler creates a MonitoringHandler.
func NewMonitoringHandler(store *repository.Store, authz *services.AuthorizationService, scheduler *services.MonitoringScheduler, audit *services.AuditService, staleAfter time.Duration) *MonitoringHandler {
	return &MonitoringHandler{store: store, authz: authz, scheduler: scheduler, audit: audit, staleAfter: staleAfter}
}

// authorizeVMView resolves :id and checks vm.view for the caller,
// returning the joined VM detail row (which already carries
// connection_status/resource status) on success. Existence and
// authorization failures are indistinguishable (404), matching every
// other VM-scoped GET in this project.
func (h *MonitoringHandler) authorizeVMView(w http.ResponseWriter, r *http.Request) (generated.GetVMDetailByResourceIDRow, uuid.UUID, bool) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return generated.GetVMDetailByResourceIDRow{}, uuid.Nil, false
	}
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return generated.GetVMDetailByResourceIDRow{}, uuid.Nil, false
	}
	allowed, err := h.authz.CanAccessVMAny(r.Context(), user, resourceID, services.PermVMView, services.PermVMMetrics)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return generated.GetVMDetailByResourceIDRow{}, uuid.Nil, false
	}
	if !allowed {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return generated.GetVMDetailByResourceIDRow{}, uuid.Nil, false
	}
	detail, err := h.store.GetVMDetailByResourceID(r.Context(), resourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return generated.GetVMDetailByResourceIDRow{}, uuid.Nil, false
	}
	return detail, resourceID, true
}

// --- response DTOs (Step 6 spec §37) ---

type cpuDTO struct {
	UsagePercent  *float64 `json:"usage_percent,omitempty"`
	UserPercent   *float64 `json:"user_percent,omitempty"`
	SystemPercent *float64 `json:"system_percent,omitempty"`
	IOWaitPercent *float64 `json:"iowait_percent,omitempty"`
	IdlePercent   *float64 `json:"idle_percent,omitempty"`
	Cores         *int32   `json:"cores,omitempty"`
}

type memoryDTO struct {
	TotalBytes     *int64   `json:"total_bytes,omitempty"`
	UsedBytes      *int64   `json:"used_bytes,omitempty"`
	AvailableBytes *int64   `json:"available_bytes,omitempty"`
	UsagePercent   *float64 `json:"usage_percent,omitempty"`
}

type swapDTO struct {
	Configured   bool     `json:"configured"`
	TotalBytes   *int64   `json:"total_bytes,omitempty"`
	UsedBytes    *int64   `json:"used_bytes,omitempty"`
	UsagePercent *float64 `json:"usage_percent,omitempty"`
}

type loadDTO struct {
	OneMinute      *float64 `json:"one_minute,omitempty"`
	FiveMinutes    *float64 `json:"five_minutes,omitempty"`
	FifteenMinutes *float64 `json:"fifteen_minutes,omitempty"`
	LoadPerCPU     *float64 `json:"load_per_cpu,omitempty"`
}

type storageDTO struct {
	TotalBytes   *int64   `json:"total_bytes,omitempty"`
	UsedBytes    *int64   `json:"used_bytes,omitempty"`
	UsagePercent *float64 `json:"usage_percent,omitempty"`
}

type networkSummaryDTO struct {
	RxBytesPerSec *float64 `json:"rx_bytes_per_sec,omitempty"`
	TxBytesPerSec *float64 `json:"tx_bytes_per_sec,omitempty"`
}

type filesystemDTO struct {
	MountPoint     string  `json:"mount_point"`
	Filesystem     string  `json:"filesystem,omitempty"`
	TotalBytes     int64   `json:"total_bytes"`
	UsedBytes      int64   `json:"used_bytes"`
	AvailableBytes int64   `json:"available_bytes"`
	UsagePercent   float64 `json:"usage_percent"`
}

type networkInterfaceDTO struct {
	Name          string   `json:"name"`
	RxBytesPerSec *float64 `json:"rx_bytes_per_sec,omitempty"`
	TxBytesPerSec *float64 `json:"tx_bytes_per_sec,omitempty"`
	RxErrors      int64    `json:"rx_errors"`
	TxErrors      int64    `json:"tx_errors"`
	RxDropped     int64    `json:"rx_dropped"`
	TxDropped     int64    `json:"tx_dropped"`
}

type processDTO struct {
	Total    *int32 `json:"total,omitempty"`
	Running  *int32 `json:"running,omitempty"`
	Sleeping *int32 `json:"sleeping,omitempty"`
	Zombie   *int32 `json:"zombie,omitempty"`
}

type monitoringCurrentResponse struct {
	Status            string                `json:"status"`
	CapturedAt        *string               `json:"captured_at,omitempty"`
	StaleAfterSeconds int64                 `json:"stale_after_seconds"`
	MonitoringEnabled bool                  `json:"monitoring_enabled"`
	CPU               *cpuDTO               `json:"cpu,omitempty"`
	Memory            *memoryDTO            `json:"memory,omitempty"`
	Swap              *swapDTO              `json:"swap,omitempty"`
	Load              *loadDTO              `json:"load,omitempty"`
	UptimeSeconds     *int64                `json:"uptime_seconds,omitempty"`
	Storage           *storageDTO           `json:"storage,omitempty"`
	Network           *networkSummaryDTO    `json:"network,omitempty"`
	Filesystems       []filesystemDTO       `json:"filesystems,omitempty"`
	NetworkInterfaces []networkInterfaceDTO `json:"network_interfaces,omitempty"`
	Process           *processDTO           `json:"process,omitempty"`
	LastRunStatus     string                `json:"last_run_status,omitempty"`
	LastRunError      string                `json:"last_run_error,omitempty"`
}

// GetCurrent handles GET /api/vms/:id/monitoring/current.
func (h *MonitoringHandler) GetCurrent(w http.ResponseWriter, r *http.Request) {
	vm, resourceID, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}

	resp := monitoringCurrentResponse{
		StaleAfterSeconds: int64(h.staleAfter.Seconds()),
		MonitoringEnabled: vm.MonitoringEnabled,
	}

	snapshot, err := h.store.GetLatestMonitoringSnapshot(r.Context(), resourceID)
	hasSnapshot := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load monitoring data")
		return
	}

	connectionHealthy := vm.ConnectionStatus == "CONNECTED"
	storedHealth := services.HealthUnknown
	if hasSnapshot {
		storedHealth = services.HealthStatus(pgutil.TextOrEmpty(snapshot.Status))
	}
	resp.Status = string(services.DeriveDisplayHealth(hasSnapshot, connectionHealthy, storedHealth))

	if hasSnapshot {
		formatted := snapshot.CapturedAt.Time.Format(time.RFC3339)
		resp.CapturedAt = &formatted

		resp.CPU = &cpuDTO{
			UsagePercent: pgutil.Float8Ptr(snapshot.CpuUsagePercent), UserPercent: pgutil.Float8Ptr(snapshot.CpuUserPercent),
			SystemPercent: pgutil.Float8Ptr(snapshot.CpuSystemPercent), IOWaitPercent: pgutil.Float8Ptr(snapshot.CpuIowaitPercent),
			IdlePercent: pgutil.Float8Ptr(snapshot.CpuIdlePercent), Cores: pgutil.Int4Ptr(snapshot.CpuCores),
		}
		resp.Memory = &memoryDTO{
			TotalBytes: pgutil.Int8Ptr(snapshot.MemoryTotalBytes), UsedBytes: pgutil.Int8Ptr(snapshot.MemoryUsedBytes),
			UsagePercent: memoryUsagePercent(snapshot),
		}
		if av := memoryAvailable(snapshot); av != nil {
			resp.Memory.AvailableBytes = av
		}
		resp.Swap = swapDTOFrom(snapshot)
		resp.Load = &loadDTO{
			OneMinute: pgutil.Float8Ptr(snapshot.Load1m), FiveMinutes: pgutil.Float8Ptr(snapshot.Load5m), FifteenMinutes: pgutil.Float8Ptr(snapshot.Load15m),
		}
		if snapshot.Load1m.Valid && snapshot.CpuCores.Valid && snapshot.CpuCores.Int32 > 0 {
			perCPU := snapshot.Load1m.Float64 / float64(snapshot.CpuCores.Int32)
			resp.Load.LoadPerCPU = &perCPU
		}
		resp.UptimeSeconds = pgutil.Int8Ptr(snapshot.UptimeSeconds)
		resp.Storage = &storageDTO{
			TotalBytes: pgutil.Int8Ptr(snapshot.StorageTotalBytes), UsedBytes: pgutil.Int8Ptr(snapshot.StorageUsedBytes),
			UsagePercent: storageUsagePercent(snapshot),
		}
		if snapshot.NetworkRxRateBytes.Valid || snapshot.NetworkTxRateBytes.Valid {
			resp.Network = &networkSummaryDTO{
				RxBytesPerSec: int8PtrToFloat64Ptr(snapshot.NetworkRxRateBytes),
				TxBytesPerSec: int8PtrToFloat64Ptr(snapshot.NetworkTxRateBytes),
			}
		}
		resp.Process = &processDTO{
			Total: pgutil.Int4Ptr(snapshot.ProcessCount), Running: pgutil.Int4Ptr(snapshot.ProcessRunningCount),
			Sleeping: pgutil.Int4Ptr(snapshot.ProcessSleepingCount), Zombie: pgutil.Int4Ptr(snapshot.ProcessZombieCount),
		}
	}

	if filesystems, err := h.store.ListLatestVMFilesystems(r.Context(), vm.VmID); err == nil {
		for _, f := range filesystems {
			resp.Filesystems = append(resp.Filesystems, filesystemDTO{
				MountPoint: f.MountPoint, Filesystem: pgutil.TextOrEmpty(f.Filesystem),
				TotalBytes: int8OrZero(f.TotalBytes), UsedBytes: int8OrZero(f.UsedBytes),
				AvailableBytes: int8OrZero(f.AvailableBytes), UsagePercent: float8OrZero(f.UsagePercent),
			})
		}
	}

	if interfaces, err := h.store.ListLatestVMNetworkSnapshots(r.Context(), vm.VmID); err == nil {
		for _, n := range interfaces {
			resp.NetworkInterfaces = append(resp.NetworkInterfaces, networkInterfaceDTO{
				Name: n.InterfaceName, RxBytesPerSec: int8PtrToFloat64Ptr(n.RxRateBytes), TxBytesPerSec: int8PtrToFloat64Ptr(n.TxRateBytes),
				RxErrors: n.RxErrors, TxErrors: n.TxErrors, RxDropped: n.RxDropped, TxDropped: n.TxDropped,
			})
		}
	}

	if runs, err := h.store.ListMonitoringRunsByVM(r.Context(), generated.ListMonitoringRunsByVMParams{VmID: vm.VmID, Limit: 1}); err == nil && len(runs) > 0 {
		resp.LastRunStatus = runs[0].Status
		resp.LastRunError = pgutil.TextOrEmpty(runs[0].ErrorSummary)
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

// GetHistory handles GET /api/vms/:id/monitoring/history?from=&to=&limit=.
func (h *MonitoringHandler) GetHistory(w http.ResponseWriter, r *http.Request) {
	vm, resourceID, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}

	now := time.Now()
	from := now.Add(-defaultHistoryRange)
	to := now
	if v := r.URL.Query().Get("from"); v != "" {
		if parsed, err := time.Parse(time.RFC3339, v); err == nil {
			from = parsed
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if parsed, err := time.Parse(time.RFC3339, v); err == nil {
			to = parsed
		}
	}
	if to.Before(from) {
		httpx.WriteError(w, http.StatusBadRequest, "to must not be before from")
		return
	}
	if to.Sub(from) > maxHistoryRange {
		from = to.Add(-maxHistoryRange)
	}

	limit := int32(defaultHistoryLimit)
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			limit = int32(parsed)
		}
	}
	if limit > maxHistoryLimit {
		limit = maxHistoryLimit
	}

	snapshots, err := h.store.ListMonitoringSnapshotsByResourceRange(r.Context(), generated.ListMonitoringSnapshotsByResourceRangeParams{
		ResourceID: resourceID, CapturedAt: pgutil.Timestamptz(from), CapturedAt_2: pgutil.Timestamptz(to), Limit: limit,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load monitoring history")
		return
	}

	type point struct {
		CapturedAt     string   `json:"captured_at"`
		Status         string   `json:"status,omitempty"`
		CPUPercent     *float64 `json:"cpu_usage_percent,omitempty"`
		MemoryPercent  *float64 `json:"memory_usage_percent,omitempty"`
		StoragePercent *float64 `json:"storage_usage_percent,omitempty"`
		NetworkRxRate  *int64   `json:"network_rx_rate_bytes,omitempty"`
		NetworkTxRate  *int64   `json:"network_tx_rate_bytes,omitempty"`
	}
	points := make([]point, 0, len(snapshots))
	for _, s := range snapshots {
		points = append(points, point{
			CapturedAt: s.CapturedAt.Time.Format(time.RFC3339), Status: pgutil.TextOrEmpty(s.Status),
			CPUPercent: pgutil.Float8Ptr(s.CpuUsagePercent), MemoryPercent: memoryUsagePercent(s),
			StoragePercent: storageUsagePercent(s), NetworkRxRate: pgutil.Int8Ptr(s.NetworkRxRateBytes), NetworkTxRate: pgutil.Int8Ptr(s.NetworkTxRateBytes),
		})
	}

	_ = vm
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"from": from.Format(time.RFC3339), "to": to.Format(time.RFC3339), "points": points,
	})
}

type collectResponse struct {
	Status       string `json:"status"`
	Health       string `json:"health,omitempty"`
	ErrorSummary string `json:"error_summary,omitempty"`
}

// Collect handles POST /api/vms/:id/monitoring/collect (admin-only,
// rate-limited -- Step 6 spec §48). Like TestConnection/Discover, this is
// an operation endpoint: request-level problems (not found, not
// authorized) use HTTP error statuses; the collection outcome itself is
// always conveyed in a 200 body.
func (h *MonitoringHandler) Collect(w http.ResponseWriter, r *http.Request) {
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	if _, err := h.store.GetVMResourceByID(r.Context(), resourceID); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}

	result, err := h.scheduler.CollectNow(r.Context(), resourceID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrMonitoringInProgress), errors.Is(err, services.ErrMonitoringRateLimited):
			httpx.WriteError(w, http.StatusTooManyRequests, err.Error())
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "collection failed")
		}
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditMonitoringCollectTriggered, ResourceType: "VM", ResourceID: &resourceID,
		Metadata: map[string]any{"status": result.Status},
	})

	httpx.WriteJSON(w, http.StatusOK, collectResponse{Status: result.Status, Health: string(result.Health), ErrorSummary: result.ErrorSummary})
}

// --- small pgtype conversion helpers local to this file ---

func memoryUsagePercent(s generated.MonitoringSnapshot) *float64 {
	if !s.MemoryTotalBytes.Valid || !s.MemoryUsedBytes.Valid || s.MemoryTotalBytes.Int64 == 0 {
		return nil
	}
	pct := 100 * float64(s.MemoryUsedBytes.Int64) / float64(s.MemoryTotalBytes.Int64)
	return &pct
}

func memoryAvailable(s generated.MonitoringSnapshot) *int64 {
	if !s.MemoryTotalBytes.Valid || !s.MemoryUsedBytes.Valid {
		return nil
	}
	v := s.MemoryTotalBytes.Int64 - s.MemoryUsedBytes.Int64
	return &v
}

func storageUsagePercent(s generated.MonitoringSnapshot) *float64 {
	if !s.StorageTotalBytes.Valid || !s.StorageUsedBytes.Valid || s.StorageTotalBytes.Int64 == 0 {
		return nil
	}
	pct := 100 * float64(s.StorageUsedBytes.Int64) / float64(s.StorageTotalBytes.Int64)
	return &pct
}

func swapDTOFrom(s generated.MonitoringSnapshot) *swapDTO {
	if !s.SwapTotalBytes.Valid || s.SwapTotalBytes.Int64 == 0 {
		return &swapDTO{Configured: false}
	}
	pct := 100 * float64(s.SwapUsedBytes.Int64) / float64(s.SwapTotalBytes.Int64)
	return &swapDTO{
		Configured: true, TotalBytes: pgutil.Int8Ptr(s.SwapTotalBytes), UsedBytes: pgutil.Int8Ptr(s.SwapUsedBytes), UsagePercent: &pct,
	}
}

// int8OrZero/float8OrZero render a possibly-NULL numeric column as a plain
// zero value -- used only for the per-filesystem list, where every row
// came from a successful df parse and NULL genuinely means "not
// collected for this mount," which is indistinguishable from 0 for
// display purposes here (unlike the current-snapshot fields above, which
// use pointers specifically to distinguish "0" from "not collected").
func int8OrZero(v pgtype.Int8) int64 {
	if !v.Valid {
		return 0
	}
	return v.Int64
}

func float8OrZero(v pgtype.Float8) float64 {
	if !v.Valid {
		return 0
	}
	return v.Float64
}

// int8PtrToFloat64Ptr renders an integer byte-rate column (stored as
// pgtype.Int8) as *float64, matching the other rate/percent fields in
// these DTOs, which are all floats.
func int8PtrToFloat64Ptr(v pgtype.Int8) *float64 {
	if !v.Valid {
		return nil
	}
	f := float64(v.Int64)
	return &f
}
