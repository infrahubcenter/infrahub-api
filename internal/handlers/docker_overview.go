// Package handlers: docker_overview.go implements Step 24's new top-level
// Docker Monitoring dashboard (GET /api/docker/overview) -- a cross-VM
// container list with live metrics, replacing the old "you can only see
// Docker per-VM" navigation with one dashboard across every VM the caller
// can see. Reuses DockerHandler's existing store/cache/staleAfter
// unchanged (the exact same data ListRunningDockerContainersByVM +
// DockerMetricsCache already serve per-VM); the only new piece is who's
// allowed to see which containers -- gated by
// AuthorizationService.CanAccessDockerFeature (docker.monitor), a
// Project/Group-scoped grant deliberately independent of vm.view.
package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/services"
)

// unnamedAppLabel is what a Member sees in place of a display name that
// was never set -- never the container/VM's real identity (see
// dockerOverviewContainerDTO's redaction rule below), and a clear signal
// to the admin that this app still needs a name before it's meaningfully
// shareable.
const unnamedAppLabel = "Unnamed App"

type dockerOverviewContainerDTO struct {
	ContainerID string `json:"container_id"`
	// ContainerName/VMName/RealContainerID are the real Docker/VM identity
	// -- Admin-only (see the redaction rule in MonitoringOverview below).
	// A Member's response always has these empty (omitted from the JSON)
	// and relies entirely on DisplayName instead, per the "a member should
	// see the app name they were granted access to, never the underlying
	// VM or container name" requirement.
	ContainerName   string           `json:"container_name,omitempty"`
	RealContainerID string           `json:"real_container_id,omitempty"`
	DisplayName     string           `json:"display_name"`
	Image           string           `json:"image"`
	ImageTag        string           `json:"image_tag,omitempty"`
	Status          string           `json:"status"`
	VMResourceID    string           `json:"vm_resource_id,omitempty"`
	VMName          string           `json:"vm_name,omitempty"`
	WorkspaceName   string           `json:"workspace_name"`
	CreatedAtRemote *string          `json:"created_at_remote,omitempty"`
	Metrics         *dockerMetricDTO `json:"metrics,omitempty"`
}

// MonitoringOverview handles GET /api/docker/overview: every container
// the caller may monitor, across every VM, each with its latest cached
// metrics sample (never a new SSH command -- same cache every per-VM
// endpoint already reads). Admin sees everything, including which VM and
// which real container this is. A Member sees only containers on VMs
// within a Project/Group they hold a docker.monitor grant on, and even
// then only ever sees the custom App Name (see unnamedAppLabel) -- never
// the VM name or the container's real name, which stay Admin-only
// infrastructure detail. Distinct from the existing (per-VM)
// DockerHandler.Overview above, which reports one VM's Docker daemon
// status/version.
func (h *DockerHandler) MonitoringOverview(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	isAdmin := user.IsAdmin()

	resourceIDs, err := h.authz.AccessibleVMResourceIDsForDockerFeature(r.Context(), user, services.PermDockerMonitor)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return
	}

	// Optional narrowing to one VM -- used by a Dashboard's Monitoring tab
	// (see handlers/dashboards.go), which is already scoped to exactly one
	// bound VM by DashboardService.CanView before the frontend ever calls
	// this endpoint with the param set. A caller who can't actually access
	// vm_resource_id (guessed or stale) just gets an empty list, same as
	// every other cross-resource filter in this app -- no separate 403.
	if filter := r.URL.Query().Get("vm_resource_id"); filter != "" {
		filterID, err := uuid.Parse(filter)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid vm_resource_id")
			return
		}
		if isAdmin || containsUUID(resourceIDs, filterID) {
			resourceIDs = []uuid.UUID{filterID}
		} else {
			resourceIDs = []uuid.UUID{}
		}
	}

	rows, err := h.store.ListDockerContainersForResourceIDs(r.Context(), resourceIDs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load containers")
		return
	}

	items := make([]dockerOverviewContainerDTO, 0, len(rows))
	for _, row := range rows {
		displayName := pgutil.TextOrEmpty(row.DisplayName)
		dto := dockerOverviewContainerDTO{
			ContainerID: row.ID.String(), Image: row.Image, ImageTag: pgutil.TextOrEmpty(row.ImageTag), Status: row.Status, WorkspaceName: row.WorkspaceName,
			CreatedAtRemote: formatTimestamptz(row.CreatedAtRemote),
		}
		if isAdmin {
			dto.ContainerName = row.Name
			dto.RealContainerID = row.ContainerID
			dto.VMResourceID = row.VmResourceID.String()
			dto.VMName = row.VmName
			dto.DisplayName = displayName
		} else if displayName != "" {
			dto.DisplayName = displayName
		} else {
			dto.DisplayName = unnamedAppLabel
		}
		if entry, ok := h.cache.Get(row.ID); ok {
			dto.Metrics = statsToMetricDTO(row.ID, row.Name, entry.Stats, entry.CapturedAt, time.Since(entry.CapturedAt) > h.staleAfter)
		}
		items = append(items, dto)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"containers": items})
}

type setDisplayNameRequest struct {
	DisplayName string `json:"display_name"`
}

// SetContainerDisplayName handles PUT /api/docker/containers/:containerId/name
// -- Admin-only. An empty display_name clears the custom "App Name" label,
// reverting display to the container's real name everywhere (Monitoring,
// Logs). Purely cosmetic -- never touched by discovery, and never affects
// authorization/access-grant matching (which is still keyed on the
// container's real identity).
func (h *DockerHandler) SetContainerDisplayName(w http.ResponseWriter, r *http.Request) {
	containerID, err := uuid.Parse(r.PathValue("containerId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "container not found")
		return
	}
	var req setDisplayNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	trimmed := strings.TrimSpace(req.DisplayName)
	var displayName pgtype.Text
	if trimmed != "" {
		displayName = pgutil.Text(trimmed)
	}

	updated, err := h.store.SetDockerContainerDisplayName(r.Context(), generated.SetDockerContainerDisplayNameParams{
		ID: containerID, DisplayName: displayName,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.WriteError(w, http.StatusNotFound, "container not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to update display name")
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditDockerContainerRenamed, ResourceType: "DOCKER_CONTAINER", ResourceID: &containerID,
		Metadata: map[string]any{"container_name": updated.Name, "display_name": trimmed},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id": updated.ID.String(), "name": updated.Name, "display_name": pgutil.TextOrEmpty(updated.DisplayName),
	})
}

func containsUUID(ids []uuid.UUID, target uuid.UUID) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}
