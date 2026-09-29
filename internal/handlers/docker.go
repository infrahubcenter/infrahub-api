package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

const (
	defaultDockerHistoryRange = 1 * time.Hour
	maxDockerHistoryRange     = 24 * time.Hour
	defaultDockerHistoryLimit = 500
	maxDockerHistoryLimit     = 2000
)

// DockerHandler implements the Step 8 Docker discovery/inventory/metrics
// REST API. Every GET individually checks vm.view (spec §63); scan is
// admin-only (spec §61), enforced in router.go via requireAdmin. Every
// container-scoped endpoint additionally verifies the requested container
// actually belongs to the requested VM (spec §75's IDOR requirement) via
// GetDockerContainerByID's (id, vm_id) WHERE clause, never a bare lookup
// by container ID alone.
type DockerHandler struct {
	store          *repository.Store
	authz          *services.AuthorizationService
	scheduler      *services.DockerDiscoveryScheduler
	cache          *services.DockerMetricsCache
	audit          *services.AuditService
	staleAfter     time.Duration
	streamInterval time.Duration
	frontendOrigin string
}

// NewDockerHandler creates a DockerHandler. streamInterval is
// DOCKER_STATS_STREAM_INTERVAL (the WebSocket push cadence); frontendOrigin
// is the same configured origin middleware.CORS enforces for regular
// requests, checked against the WebSocket handshake's Origin header since
// browsers don't apply CORS to WebSocket upgrades themselves.
func NewDockerHandler(store *repository.Store, authz *services.AuthorizationService, scheduler *services.DockerDiscoveryScheduler, cache *services.DockerMetricsCache, audit *services.AuditService, staleAfter, streamInterval time.Duration, frontendOrigin string) *DockerHandler {
	return &DockerHandler{
		store: store, authz: authz, scheduler: scheduler, cache: cache, audit: audit,
		staleAfter: staleAfter, streamInterval: streamInterval, frontendOrigin: frontendOrigin,
	}
}

// authorizeVMView resolves :id and checks vm.view, returning the VM's
// resource ID and the vms row itself (which carries every
// docker_daemon_status/docker_*_version/docker_info column directly --
// no separate lookup needed). 404-not-403 on failure, matching every
// other VM-scoped endpoint since Step 3.
func (h *DockerHandler) authorizeVMView(w http.ResponseWriter, r *http.Request) (resourceID uuid.UUID, vm generated.Vm, ok bool) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return uuid.Nil, generated.Vm{}, false
	}
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return uuid.Nil, generated.Vm{}, false
	}
	allowed, err := h.authz.CanAccessVM(r.Context(), user, resourceID, services.PermVMView)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return uuid.Nil, generated.Vm{}, false
	}
	if !allowed {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return uuid.Nil, generated.Vm{}, false
	}
	vmRow, err := h.store.GetVMByResourceID(r.Context(), resourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return uuid.Nil, generated.Vm{}, false
	}
	return resourceID, vmRow, true
}

// authorizeContainer additionally resolves :containerId and verifies it
// belongs to vm -- the IDOR-safety check spec §75 requires on every
// container-scoped endpoint (a container that genuinely exists but on a
// different VM must 404, exactly like a container that doesn't exist at
// all).
func (h *DockerHandler) authorizeContainer(w http.ResponseWriter, r *http.Request, vmRowID uuid.UUID) (generated.DockerContainer, bool) {
	containerID, err := uuid.Parse(r.PathValue("containerId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "container not found")
		return generated.DockerContainer{}, false
	}
	container, err := h.store.GetDockerContainerByID(r.Context(), generated.GetDockerContainerByIDParams{ID: containerID, VmID: vmRowID})
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "container not found")
		return generated.DockerContainer{}, false
	}
	return container, true
}

// --- DTOs ---

type dockerOverviewDTO struct {
	DaemonStatus  string         `json:"daemon_status"`
	EngineVersion string         `json:"engine_version,omitempty"`
	APIVersion    string         `json:"api_version,omitempty"`
	CLIVersion    string         `json:"cli_version,omitempty"`
	Info          map[string]any `json:"info,omitempty"`
	LastScan      *scanRunDTO    `json:"last_scan,omitempty"`
}

type scanRunDTO struct {
	Status         string  `json:"status"`
	ContainerCount *int32  `json:"container_count,omitempty"`
	ImageCount     *int32  `json:"image_count,omitempty"`
	NetworkCount   *int32  `json:"network_count,omitempty"`
	VolumeCount    *int32  `json:"volume_count,omitempty"`
	StartedAt      string  `json:"started_at"`
	CompletedAt    *string `json:"completed_at,omitempty"`
	ErrorSummary   *string `json:"error_summary,omitempty"`
}

func toScanRunDTO(run generated.DockerDiscoveryRun) scanRunDTO {
	dto := scanRunDTO{
		Status: run.Status, ContainerCount: pgutil.Int4Ptr(run.ContainerCount), ImageCount: pgutil.Int4Ptr(run.ImageCount),
		NetworkCount: pgutil.Int4Ptr(run.NetworkCount), VolumeCount: pgutil.Int4Ptr(run.VolumeCount),
		StartedAt: run.StartedAt.Time.Format(time.RFC3339), ErrorSummary: pgutil.StringPtr(run.ErrorSummary),
	}
	dto.CompletedAt = formatTimestamptz(run.CompletedAt)
	return dto
}

// Overview handles GET /api/vms/:id/docker.
func (h *DockerHandler) Overview(w http.ResponseWriter, r *http.Request) {
	_, vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	resp := dockerOverviewDTO{
		DaemonStatus: pgutil.TextOrEmpty(vm.DockerDaemonStatus), EngineVersion: pgutil.TextOrEmpty(vm.DockerEngineVersion),
		APIVersion: pgutil.TextOrEmpty(vm.DockerApiVersion), CLIVersion: pgutil.TextOrEmpty(vm.DockerCliVersion),
	}
	if resp.DaemonStatus == "" {
		resp.DaemonStatus = "UNKNOWN" // never scanned yet
	}
	if len(vm.DockerInfo) > 0 {
		var info map[string]any
		if err := json.Unmarshal(vm.DockerInfo, &info); err == nil && len(info) > 0 {
			resp.Info = info
		}
	}
	if run, err := h.store.GetLatestDockerDiscoveryRun(r.Context(), vm.ID); err == nil {
		dto := toScanRunDTO(run)
		resp.LastScan = &dto
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

type dockerSummaryDTO struct {
	ContainersTotal     int64       `json:"containers_total"`
	ContainersRunning   int64       `json:"containers_running"`
	ContainersStopped   int64       `json:"containers_stopped"`
	ContainersUnhealthy int64       `json:"containers_unhealthy"`
	ImagesTotal         int64       `json:"images_total"`
	NetworksTotal       int64       `json:"networks_total"`
	VolumesTotal        int64       `json:"volumes_total"`
	LastScan            *scanRunDTO `json:"last_scan,omitempty"`
}

// Summary handles GET /api/vms/:id/docker/summary.
func (h *DockerHandler) Summary(w http.ResponseWriter, r *http.Request) {
	_, vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	resp := dockerSummaryDTO{}
	if s, err := h.store.GetDockerSummaryByVM(r.Context(), vm.ID); err == nil {
		resp.ContainersTotal, resp.ContainersRunning = s.Total, s.Running
		resp.ContainersStopped, resp.ContainersUnhealthy = s.Stopped, s.Unhealthy
	}
	if n, err := h.store.CountDockerImagesByVM(r.Context(), vm.ID); err == nil {
		resp.ImagesTotal = n
	}
	if n, err := h.store.CountDockerNetworksByVM(r.Context(), vm.ID); err == nil {
		resp.NetworksTotal = n
	}
	if n, err := h.store.CountDockerVolumesByVM(r.Context(), vm.ID); err == nil {
		resp.VolumesTotal = n
	}
	if run, err := h.store.GetLatestDockerDiscoveryRun(r.Context(), vm.ID); err == nil {
		dto := toScanRunDTO(run)
		resp.LastScan = &dto
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

type dockerPortDTO struct {
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      int    `json:"host_port,omitempty"`
}

type dockerMountDTO struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	ReadOnly    bool   `json:"read_only"`
	Type        string `json:"type,omitempty"`
}

type dockerContainerDTO struct {
	ID               string                       `json:"id"`
	ContainerID      string                       `json:"container_id"`
	Name             string                       `json:"name"`
	// DisplayName is the admin-set custom label (docker_containers.
	// display_name, see docker_logs.sql's SetDockerContainerDisplayName) --
	// empty when none has been set, in which case callers fall back to
	// Name. Lets a container-picker show "Backend API (nginx_1a2b3c)"
	// instead of the raw container name alone.
	DisplayName      string                       `json:"display_name,omitempty"`
	Image            string                       `json:"image"`
	ImageTag         string                       `json:"image_tag,omitempty"`
	Status           string                       `json:"status"`
	State            string                       `json:"state,omitempty"`
	Health           string                       `json:"health,omitempty"`
	Command          string                       `json:"command,omitempty"`
	RestartCount     *int32                       `json:"restart_count,omitempty"`
	Platform         string                       `json:"platform,omitempty"`
	Ports            []dockerPortDTO              `json:"ports,omitempty"`
	Mounts           []dockerMountDTO             `json:"mounts,omitempty"`
	CreatedAtRemote  *string                      `json:"created_at_remote,omitempty"`
	StartedAtRemote  *string                      `json:"started_at_remote,omitempty"`
	LastDiscoveredAt *string                      `json:"last_discovered_at,omitempty"`
	Networks         []dockerNetworkMembershipDTO `json:"networks,omitempty"`
}

type dockerNetworkMembershipDTO struct {
	NetworkName string `json:"network_name"`
	Driver      string `json:"driver,omitempty"`
	IPAddress   string `json:"ip_address,omitempty"`
	Gateway     string `json:"gateway,omitempty"`
	MacAddress  string `json:"mac_address,omitempty"`
}

func toDockerContainerDTO(c generated.DockerContainer) dockerContainerDTO {
	dto := dockerContainerDTO{
		ID: c.ID.String(), ContainerID: c.ContainerID, Name: c.Name, DisplayName: pgutil.TextOrEmpty(c.DisplayName),
		Image: c.Image, ImageTag: pgutil.TextOrEmpty(c.ImageTag),
		Status: c.Status, State: pgutil.TextOrEmpty(c.State), Health: pgutil.TextOrEmpty(c.Health),
		Command: pgutil.TextOrEmpty(c.Command), RestartCount: pgutil.Int4Ptr(c.RestartCount), Platform: pgutil.TextOrEmpty(c.Platform),
		CreatedAtRemote: formatTimestamptz(c.CreatedAtRemote), StartedAtRemote: formatTimestamptz(c.StartedAtRemote),
		LastDiscoveredAt: formatTimestamptz(c.LastDiscoveredAt),
	}
	var ports []dockerPortDTO
	if err := json.Unmarshal(c.Ports, &ports); err == nil {
		dto.Ports = ports
	}
	var mounts []dockerMountDTO
	if err := json.Unmarshal(c.Mounts, &mounts); err == nil {
		dto.Mounts = mounts
	}
	return dto
}

// ListContainers handles GET /api/vms/:id/docker/containers?search=&status=&health=&page=&page_size=.
func (h *DockerHandler) ListContainers(w http.ResponseWriter, r *http.Request) {
	_, vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	limit, offset, page, pageSize := pagination(r)
	q := r.URL.Query()
	params := generated.ListDockerContainersByVMParams{
		VmID: vm.ID, Limit: limit, Offset: offset,
		Search: optionalText(q.Get("search")), Status: optionalText(q.Get("status")), Health: optionalText(q.Get("health")),
	}
	rows, err := h.store.ListDockerContainersByVM(r.Context(), params)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load containers")
		return
	}
	total, err := h.store.CountDockerContainersByVM(r.Context(), generated.CountDockerContainersByVMParams{
		VmID: vm.ID, Search: params.Search, Status: params.Status, Health: params.Health,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to count containers")
		return
	}
	items := make([]dockerContainerDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, toDockerContainerDTO(row))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"containers": items, "page": page, "page_size": pageSize, "total": total,
	})
}

// GetContainer handles GET /api/vms/:id/docker/containers/:containerId.
func (h *DockerHandler) GetContainer(w http.ResponseWriter, r *http.Request) {
	_, vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	container, ok := h.authorizeContainer(w, r, vm.ID)
	if !ok {
		return
	}
	dto := toDockerContainerDTO(container)
	if networks, err := h.store.ListNetworksForContainer(r.Context(), container.ID); err == nil {
		for _, n := range networks {
			dto.Networks = append(dto.Networks, dockerNetworkMembershipDTO{
				NetworkName: n.Name, Driver: pgutil.TextOrEmpty(n.Driver), IPAddress: pgutil.TextOrEmpty(n.IpAddress),
				Gateway: pgutil.TextOrEmpty(n.Gateway), MacAddress: pgutil.TextOrEmpty(n.MacAddress),
			})
		}
	}
	httpx.WriteJSON(w, http.StatusOK, dto)
}

type dockerImageDTO struct {
	ID               string  `json:"id"`
	Repository       string  `json:"repository"`
	Tag              string  `json:"tag"`
	ImageID          string  `json:"image_id"`
	Digest           string  `json:"digest,omitempty"`
	SizeBytes        *int64  `json:"size_bytes,omitempty"`
	CreatedAtRemote  *string `json:"created_at_remote,omitempty"`
	LastDiscoveredAt *string `json:"last_discovered_at,omitempty"`
}

// ListImages handles GET /api/vms/:id/docker/images.
func (h *DockerHandler) ListImages(w http.ResponseWriter, r *http.Request) {
	_, vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	rows, err := h.store.ListDockerImagesByVM(r.Context(), vm.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load images")
		return
	}
	items := make([]dockerImageDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, dockerImageDTO{
			ID: row.ID.String(), Repository: row.Repository, Tag: row.Tag, ImageID: row.ImageID, Digest: pgutil.TextOrEmpty(row.Digest),
			SizeBytes: pgutil.Int8Ptr(row.SizeBytes), CreatedAtRemote: formatTimestamptz(row.CreatedAtRemote),
			LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"images": items, "total": len(items)})
}

type dockerNetworkDTO struct {
	ID               string  `json:"id"`
	NetworkID        string  `json:"network_id"`
	Name             string  `json:"name"`
	Driver           string  `json:"driver,omitempty"`
	Scope            string  `json:"scope,omitempty"`
	Internal         bool    `json:"internal"`
	Attachable       bool    `json:"attachable"`
	CreatedAtRemote  *string `json:"created_at_remote,omitempty"`
	LastDiscoveredAt *string `json:"last_discovered_at,omitempty"`
}

// ListNetworks handles GET /api/vms/:id/docker/networks.
func (h *DockerHandler) ListNetworks(w http.ResponseWriter, r *http.Request) {
	_, vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	rows, err := h.store.ListDockerNetworksByVM(r.Context(), vm.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load networks")
		return
	}
	items := make([]dockerNetworkDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, dockerNetworkDTO{
			ID: row.ID.String(), NetworkID: row.NetworkID, Name: row.Name, Driver: pgutil.TextOrEmpty(row.Driver),
			Scope: pgutil.TextOrEmpty(row.Scope), Internal: row.Internal, Attachable: row.Attachable,
			CreatedAtRemote: formatTimestamptz(row.CreatedAtRemote), LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"networks": items, "total": len(items)})
}

type dockerVolumeDTO struct {
	ID               string  `json:"id"`
	Name             string  `json:"name"`
	Driver           string  `json:"driver,omitempty"`
	Mountpoint       string  `json:"mountpoint,omitempty"`
	Scope            string  `json:"scope,omitempty"`
	CreatedAtRemote  *string `json:"created_at_remote,omitempty"`
	LastDiscoveredAt *string `json:"last_discovered_at,omitempty"`
}

// ListVolumes handles GET /api/vms/:id/docker/volumes.
func (h *DockerHandler) ListVolumes(w http.ResponseWriter, r *http.Request) {
	_, vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	rows, err := h.store.ListDockerVolumesByVM(r.Context(), vm.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load volumes")
		return
	}
	items := make([]dockerVolumeDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, dockerVolumeDTO{
			ID: row.ID.String(), Name: row.VolumeName, Driver: pgutil.TextOrEmpty(row.Driver), Mountpoint: pgutil.TextOrEmpty(row.Mountpoint),
			Scope: pgutil.TextOrEmpty(row.Scope), CreatedAtRemote: formatTimestamptz(row.CreatedAtRemote),
			LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"volumes": items, "total": len(items)})
}

// Scan handles POST /api/vms/:id/docker/scan (admin-only, spec §61).
func (h *DockerHandler) Scan(w http.ResponseWriter, r *http.Request) {
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	if _, err := h.store.GetVMResourceByID(r.Context(), resourceID); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditDockerScanStarted, ResourceType: "VM", ResourceID: &resourceID,
	})

	result, err := h.scheduler.ScanNow(r.Context(), resourceID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrDockerScanInProgress), errors.Is(err, services.ErrDockerScanRateLimited):
			httpx.WriteError(w, http.StatusTooManyRequests, err.Error())
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "scan failed")
		}
		return
	}

	action := services.AuditDockerScanCompleted
	if result.Status == "FAILED" {
		action = services.AuditDockerScanFailed
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: action, ResourceType: "VM", ResourceID: &resourceID,
		Metadata: map[string]any{
			"status": result.Status, "daemon_status": string(result.DaemonStatus), "container_count": result.ContainerCount,
			"image_count": result.ImageCount, "network_count": result.NetworkCount, "volume_count": result.VolumeCount,
		},
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status": result.Status, "daemon_status": string(result.DaemonStatus), "container_count": result.ContainerCount,
		"image_count": result.ImageCount, "network_count": result.NetworkCount, "volume_count": result.VolumeCount,
		"error_summary": result.ErrorSummary,
	})
}

// --- metrics ---

type dockerMetricDTO struct {
	ContainerID      string   `json:"container_id"`
	ContainerName    string   `json:"container_name,omitempty"`
	CapturedAt       string   `json:"captured_at"`
	Stale            bool     `json:"stale"`
	CPUPercent       *float64 `json:"cpu_percent,omitempty"`
	MemoryUsageBytes *int64   `json:"memory_usage_bytes,omitempty"`
	MemoryLimitBytes *int64   `json:"memory_limit_bytes,omitempty"`
	MemoryPercent    *float64 `json:"memory_percent,omitempty"`
	NetworkRxBytes   *int64   `json:"network_rx_bytes,omitempty"`
	NetworkTxBytes   *int64   `json:"network_tx_bytes,omitempty"`
	BlockReadBytes   *int64   `json:"block_read_bytes,omitempty"`
	BlockWriteBytes  *int64   `json:"block_write_bytes,omitempty"`
	Pids             *int32   `json:"pids,omitempty"`
}

func float64Ptr(v float64) *float64 { return &v }
func int64Ptr(v int64) *int64       { return &v }
func int32Ptr(v int32) *int32       { return &v }

func statsToMetricDTO(containerID uuid.UUID, containerName string, stats services.ContainerStats, capturedAt time.Time, stale bool) *dockerMetricDTO {
	dto := &dockerMetricDTO{
		ContainerID: containerID.String(), ContainerName: containerName, CapturedAt: capturedAt.Format(time.RFC3339), Stale: stale,
		CPUPercent: float64Ptr(stats.CPUPercent), MemoryUsageBytes: int64Ptr(stats.MemoryUsageBytes),
		NetworkRxBytes: int64Ptr(stats.NetworkRxBytes), NetworkTxBytes: int64Ptr(stats.NetworkTxBytes),
		BlockReadBytes: int64Ptr(stats.BlockReadBytes), BlockWriteBytes: int64Ptr(stats.BlockWriteBytes),
		Pids: int32Ptr(int32(stats.PIDs)),
	}
	if stats.HasMemoryLimit {
		dto.MemoryLimitBytes = int64Ptr(stats.MemoryLimitBytes)
		dto.MemoryPercent = float64Ptr(stats.MemoryPercent)
	}
	return dto
}

// MetricsCurrent handles GET /api/vms/:id/docker/metrics/current -- the
// latest sample for every currently-running container on the VM, read
// from the shared cache (never a new SSH command, spec §54).
func (h *DockerHandler) MetricsCurrent(w http.ResponseWriter, r *http.Request) {
	_, vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	running, err := h.store.ListRunningDockerContainersByVM(r.Context(), vm.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load running containers")
		return
	}
	items := make([]dockerMetricDTO, 0, len(running))
	for _, c := range running {
		if dto := h.currentMetricDTOSimple(r, c.ID, c.Name); dto != nil {
			items = append(items, *dto)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"metrics": items})
}

// currentMetricDTOSimple is the same lookup as currentMetricDTO, written
// directly against *http.Request to avoid the httpRequestContext
// indirection for the common call sites.
func (h *DockerHandler) currentMetricDTOSimple(r *http.Request, containerID uuid.UUID, containerName string) *dockerMetricDTO {
	if entry, ok := h.cache.Get(containerID); ok {
		return statsToMetricDTO(containerID, containerName, entry.Stats, entry.CapturedAt, time.Since(entry.CapturedAt) > h.staleAfter)
	}
	snapshot, err := h.store.GetLatestDockerContainerMetricSnapshot(r.Context(), containerID)
	if err != nil {
		return nil
	}
	return &dockerMetricDTO{
		ContainerID: containerID.String(), ContainerName: containerName,
		CapturedAt: snapshot.CapturedAt.Time.Format(time.RFC3339), Stale: time.Since(snapshot.CapturedAt.Time) > h.staleAfter,
		CPUPercent: pgutil.Float8Ptr(snapshot.CpuPercent), MemoryUsageBytes: pgutil.Int8Ptr(snapshot.MemoryUsageBytes),
		MemoryLimitBytes: pgutil.Int8Ptr(snapshot.MemoryLimitBytes), MemoryPercent: pgutil.Float8Ptr(snapshot.MemoryPercent),
		NetworkRxBytes: pgutil.Int8Ptr(snapshot.NetworkRxBytes), NetworkTxBytes: pgutil.Int8Ptr(snapshot.NetworkTxBytes),
		BlockReadBytes: pgutil.Int8Ptr(snapshot.BlockReadBytes), BlockWriteBytes: pgutil.Int8Ptr(snapshot.BlockWriteBytes),
		Pids: pgutil.Int4Ptr(snapshot.Pids),
	}
}

// ContainerMetricsCurrent handles GET /api/vms/:id/docker/containers/:containerId/metrics/current.
func (h *DockerHandler) ContainerMetricsCurrent(w http.ResponseWriter, r *http.Request) {
	_, vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	container, ok := h.authorizeContainer(w, r, vm.ID)
	if !ok {
		return
	}
	dto := h.currentMetricDTOSimple(r, container.ID, container.Name)
	if dto == nil {
		httpx.WriteError(w, http.StatusNotFound, "no metrics collected yet for this container")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, dto)
}

type dockerMetricHistoryPointDTO struct {
	CapturedAt       string   `json:"captured_at"`
	CPUPercent       *float64 `json:"cpu_percent,omitempty"`
	MemoryUsageBytes *int64   `json:"memory_usage_bytes,omitempty"`
	MemoryPercent    *float64 `json:"memory_percent,omitempty"`
	NetworkRxRate    *float64 `json:"network_rx_bytes_per_sec,omitempty"`
	NetworkTxRate    *float64 `json:"network_tx_bytes_per_sec,omitempty"`
	BlockReadRate    *float64 `json:"block_read_bytes_per_sec,omitempty"`
	BlockWriteRate   *float64 `json:"block_write_bytes_per_sec,omitempty"`
	Pids             *int32   `json:"pids,omitempty"`
}

// ContainerMetricsHistory handles GET
// /api/vms/:id/docker/containers/:containerId/metrics/history?from=&to=&limit=.
// Rates are computed here, between each consecutive pair of stored rows
// (spec §38/§39: rate calculation belongs in the service/API layer, not
// storage -- docker_container_metric_snapshots only ever holds the raw
// cumulative counters `docker stats` reported).
func (h *DockerHandler) ContainerMetricsHistory(w http.ResponseWriter, r *http.Request) {
	_, vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	container, ok := h.authorizeContainer(w, r, vm.ID)
	if !ok {
		return
	}

	now := time.Now()
	from := now.Add(-defaultDockerHistoryRange)
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
	if to.Sub(from) > maxDockerHistoryRange {
		from = to.Add(-maxDockerHistoryRange)
	}
	limit := int32(defaultDockerHistoryLimit)
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			limit = int32(parsed)
		}
	}
	if limit > maxDockerHistoryLimit {
		limit = maxDockerHistoryLimit
	}

	rows, err := h.store.ListDockerContainerMetricHistory(r.Context(), generated.ListDockerContainerMetricHistoryParams{
		ContainerID: container.ID, VmID: vm.ID, CapturedAt: pgutil.Timestamptz(from), CapturedAt_2: pgutil.Timestamptz(to), Limit: limit,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load metric history")
		return
	}

	// rows come back newest-first (spec-consistent with every other
	// history query in this project); rates need oldest-first traversal,
	// so walk in reverse to compute each point's rate against the row
	// immediately before it in time.
	points := make([]dockerMetricHistoryPointDTO, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		row := rows[i]
		point := dockerMetricHistoryPointDTO{
			CapturedAt: row.CapturedAt.Time.Format(time.RFC3339), CPUPercent: pgutil.Float8Ptr(row.CpuPercent),
			MemoryUsageBytes: pgutil.Int8Ptr(row.MemoryUsageBytes), MemoryPercent: pgutil.Float8Ptr(row.MemoryPercent),
			Pids: pgutil.Int4Ptr(row.Pids),
		}
		if i < len(rows)-1 {
			prev := rows[i+1]
			elapsed := row.CapturedAt.Time.Sub(prev.CapturedAt.Time).Seconds()
			if prev.NetworkRxBytes.Valid && row.NetworkRxBytes.Valid {
				if rate, ok := services.ComputeDockerByteRate(prev.NetworkRxBytes.Int64, row.NetworkRxBytes.Int64, elapsed); ok {
					point.NetworkRxRate = &rate
				}
			}
			if prev.NetworkTxBytes.Valid && row.NetworkTxBytes.Valid {
				if rate, ok := services.ComputeDockerByteRate(prev.NetworkTxBytes.Int64, row.NetworkTxBytes.Int64, elapsed); ok {
					point.NetworkTxRate = &rate
				}
			}
			if prev.BlockReadBytes.Valid && row.BlockReadBytes.Valid {
				if rate, ok := services.ComputeDockerByteRate(prev.BlockReadBytes.Int64, row.BlockReadBytes.Int64, elapsed); ok {
					point.BlockReadRate = &rate
				}
			}
			if prev.BlockWriteBytes.Valid && row.BlockWriteBytes.Valid {
				if rate, ok := services.ComputeDockerByteRate(prev.BlockWriteBytes.Int64, row.BlockWriteBytes.Int64, elapsed); ok {
					point.BlockWriteRate = &rate
				}
			}
		}
		points[i] = point
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"from": from.Format(time.RFC3339), "to": to.Format(time.RFC3339), "points": points,
	})
}
