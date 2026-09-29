// Package handlers: vm_agent_metrics.go serves the VM Agent's pushed
// metrics -- read-only; every write happens on the push path
// (services.VMAgentService.HandleMetricsPush, called from a
// VMAgentHub worker). Fully separate from monitoring.go's SSH-collected
// series -- see migrations/052_vm_agent.sql's doc comment for why they
// are never mixed.
package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

type VMAgentMetricsHandler struct {
	store          *repository.Store
	authz          *services.AuthorizationService
	agent          *services.VMAgentService
	frontendOrigin string
}

func NewVMAgentMetricsHandler(store *repository.Store, authz *services.AuthorizationService, agent *services.VMAgentService, frontendOrigin string) *VMAgentMetricsHandler {
	return &VMAgentMetricsHandler{store: store, authz: authz, agent: agent, frontendOrigin: frontendOrigin}
}

// authorizeVMView mirrors PackageHandler.authorizeVMView exactly: any
// authenticated role, individually checked against vm.view, 404-not-403.
// Returns the full VM row (not just its ID) so callers can also read its
// agent-reported host identity (hostname/OS/kernel, see
// migrations/060_vm_agent_host_identity.sql) without a second lookup.
func (h *VMAgentMetricsHandler) authorizeVMView(w http.ResponseWriter, r *http.Request) (vm generated.Vm, ok bool) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return generated.Vm{}, false
	}
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return generated.Vm{}, false
	}
	allowed, err := h.authz.CanAccessVMAny(r.Context(), user, resourceID, services.PermVMView, services.PermVMMetrics)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return generated.Vm{}, false
	}
	if !allowed {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return generated.Vm{}, false
	}
	vm, err = h.store.GetVMByResourceID(r.Context(), resourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return generated.Vm{}, false
	}
	return vm, true
}

type vmAgentMetricsDTO struct {
	CapturedAt         string   `json:"captured_at"`
	CPUPercent         *float64 `json:"cpu_percent,omitempty"`
	CPUCores           *int32   `json:"cpu_cores,omitempty"`
	MemoryUsedBytes    *int64   `json:"memory_used_bytes,omitempty"`
	MemoryTotalBytes   *int64   `json:"memory_total_bytes,omitempty"`
	SwapUsedBytes      *int64   `json:"swap_used_bytes,omitempty"`
	SwapTotalBytes     *int64   `json:"swap_total_bytes,omitempty"`
	Load1m             *float64 `json:"load_1m,omitempty"`
	Load5m             *float64 `json:"load_5m,omitempty"`
	Load15m            *float64 `json:"load_15m,omitempty"`
	UptimeSeconds      *int64   `json:"uptime_seconds,omitempty"`
	StorageUsedBytes   *int64   `json:"storage_used_bytes,omitempty"`
	StorageTotalBytes  *int64   `json:"storage_total_bytes,omitempty"`
	NetworkRxRateBytes *int64   `json:"network_rx_rate_bytes,omitempty"`
	NetworkTxRateBytes *int64   `json:"network_tx_rate_bytes,omitempty"`
	ProcessCount       *int32   `json:"process_count,omitempty"`
	// Host identity -- current-value fields off the vms row, not the
	// snapshot (see migrations/060_vm_agent_host_identity.sql); never
	// fabricated if the agent hasn't pushed a sample carrying them yet.
	AgentOS            *string `json:"agent_os,omitempty"`
	AgentOSVersion     *string `json:"agent_os_version,omitempty"`
	AgentKernelVersion *string `json:"agent_kernel_version,omitempty"`
	AgentHostname      *string `json:"agent_hostname,omitempty"`
}

func toVMAgentMetricsDTO(row generated.VmAgentMetricSnapshot, vm generated.Vm) vmAgentMetricsDTO {
	return vmAgentMetricsDTO{
		CapturedAt: row.CapturedAt.Time.Format(time.RFC3339), CPUPercent: pgutil.Float8Ptr(row.CpuPercent),
		CPUCores: pgutil.Int4Ptr(row.CpuCores), MemoryUsedBytes: pgutil.Int8Ptr(row.MemoryUsedBytes),
		MemoryTotalBytes: pgutil.Int8Ptr(row.MemoryTotalBytes), SwapUsedBytes: pgutil.Int8Ptr(row.SwapUsedBytes),
		SwapTotalBytes: pgutil.Int8Ptr(row.SwapTotalBytes), Load1m: pgutil.Float8Ptr(row.Load1m),
		Load5m: pgutil.Float8Ptr(row.Load5m), Load15m: pgutil.Float8Ptr(row.Load15m),
		UptimeSeconds: pgutil.Int8Ptr(row.UptimeSeconds), StorageUsedBytes: pgutil.Int8Ptr(row.StorageUsedBytes),
		StorageTotalBytes: pgutil.Int8Ptr(row.StorageTotalBytes), NetworkRxRateBytes: pgutil.Int8Ptr(row.NetworkRxRateBytes),
		NetworkTxRateBytes: pgutil.Int8Ptr(row.NetworkTxRateBytes), ProcessCount: pgutil.Int4Ptr(row.ProcessCount),
		AgentOS: pgutil.StringPtr(vm.VmAgentOs), AgentOSVersion: pgutil.StringPtr(vm.VmAgentOsVersion),
		AgentKernelVersion: pgutil.StringPtr(vm.VmAgentKernelVersion), AgentHostname: pgutil.StringPtr(vm.VmAgentHostname),
	}
}

// Current handles GET /api/vms/{id}/vm-agent/metrics/current -- the
// latest agent-pushed sample, or 404 if none has ever arrived (never
// fabricated data, same discipline as monitoring.go's /current).
func (h *VMAgentMetricsHandler) Current(w http.ResponseWriter, r *http.Request) {
	vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	row, err := h.agent.LatestMetrics(r.Context(), vm.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.WriteError(w, http.StatusNotFound, "no agent metrics have been received for this VM yet")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load agent metrics")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toVMAgentMetricsDTO(row, vm))
}

// History handles GET /api/vms/{id}/vm-agent/metrics/history?minutes=60.
func (h *VMAgentMetricsHandler) History(w http.ResponseWriter, r *http.Request) {
	vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	minutes := 60
	if v := r.URL.Query().Get("minutes"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 7*24*60 {
			minutes = parsed
		}
	}
	rows, err := h.agent.MetricsHistory(r.Context(), vm.ID, time.Now().Add(-time.Duration(minutes)*time.Minute))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load agent metrics history")
		return
	}
	items := make([]vmAgentMetricsDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, toVMAgentMetricsDTO(row, vm))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"metrics": items})
}

// Stream handles GET /api/vms/{id}/vm-agent/metrics/stream -- a true
// push, not a poll: VMAgentService.SubscribeMetrics delivers a frame the
// instant the agent's own next push is persisted (see
// vm_agent.go's HandleMetricsPush), rather than re-reading on a fixed
// ticker the way Database's Live Metrics does. Sends whatever the latest
// known sample already is immediately on connect, so a viewer doesn't
// have to wait for the agent's next push cycle to see anything.
func (h *VMAgentMetricsHandler) Stream(w http.ResponseWriter, r *http.Request) {
	vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "" || origin == h.frontendOrigin
		},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	sub, cancel := h.agent.SubscribeMetrics(vm.ID)
	defer cancel()

	if row, err := h.agent.LatestMetrics(r.Context(), vm.ID); err == nil {
		if conn.WriteJSON(toVMAgentMetricsDTO(row, vm)) != nil {
			return
		}
	}

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-closed:
			return
		case row, chOk := <-sub:
			if !chOk {
				return
			}
			if conn.WriteJSON(toVMAgentMetricsDTO(row, vm)) != nil {
				return
			}
		}
	}
}
