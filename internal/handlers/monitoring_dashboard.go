package handlers

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// MonitoringDashboardHandler implements Step 19's central monitoring
// dashboard: GET /api/monitoring/overview (per-type health/alert/
// recommendation tallies) and GET /api/monitoring/resources (the unified,
// filterable VM/Database/Object Storage table). Named "Dashboard" (not
// "Monitoring") because MonitoringHandler already exists
// (vm_monitoring.go) for the per-VM /api/vms/:id/monitoring/* endpoints --
// a second `type MonitoringHandler` in this package would not compile.
//
// Both endpoints reuse the exact same authorization building blocks
// MyAccessHandler already uses (h.vms.List, scopedDatabaseAccess,
// scopedObjectStorageAccess) rather than a fourth, separately-maintained
// scoping implementation -- an unauthorized resource can never appear in
// either response for the same reason it can never appear in
// GET /api/my-access. Both routes are `authenticated` (any role), not
// `requireAdmin`: the response scoping itself is the security boundary,
// exactly like /api/alerts and /api/my-access today.
type MonitoringDashboardHandler struct {
	store         *repository.Store
	authz         *services.AuthorizationService
	vms           *services.VMService
	databases     *DatabaseHandler
	objectStorage *ObjectStorageHandler
}

// NewMonitoringDashboardHandler creates a MonitoringDashboardHandler.
// databases/objectStorage must be constructed first (router.go mirrors
// myAccessHandler's own documented construction-order constraint) so this
// handler can reuse their unexported permissionsForDatabase/
// permissionsForObjectStorage methods (via scopedDatabaseAccess/
// scopedObjectStorageAccess) instead of a third permission-resolution
// implementation.
func NewMonitoringDashboardHandler(
	store *repository.Store, authz *services.AuthorizationService, vms *services.VMService,
	databases *DatabaseHandler, objectStorage *ObjectStorageHandler,
) *MonitoringDashboardHandler {
	return &MonitoringDashboardHandler{store: store, authz: authz, vms: vms, databases: databases, objectStorage: objectStorage}
}

// monitoringResourceDTO is the one normalized shape loadAuthorizedResources
// merges every VM/Database/Object Storage row into (plan decision #4).
type monitoringResourceDTO struct {
	ID                  string   `json:"id"`
	ResourceType        string   `json:"resource_type"` // VM | DATABASE | OBJECT_STORAGE
	Name                string   `json:"name"`
	WorkspaceID         string   `json:"workspace_id"`
	WorkspaceName       string   `json:"workspace_name"`
	Health              string   `json:"health"`       // services.HealthStatus vocabulary
	Availability        string   `json:"availability"` // AVAILABLE | UNAVAILABLE | UNKNOWN -- decision #6
	ConnectionStatus    string   `json:"connection_status,omitempty"`
	MonitoringEnabled   bool     `json:"monitoring_enabled"`
	ActiveAlertSeverity *string  `json:"active_alert_severity,omitempty"`
	Permissions         []string `json:"permissions"`
	AccessSource        string   `json:"access_source,omitempty"`
	LastSeenAt          *string  `json:"last_seen_at,omitempty"`

	// resourceID is the underlying resources.id row this entry is
	// authorized against -- identical to ID for a VM (whose public "id" IS
	// its resource_id, per vmSummary/toVMSummary) but distinct from ID for
	// a Database/Object Storage (whose public "id" is the databases/
	// object_storages table's own PK, matching GET /api/databases's and
	// GET /api/object-storage's existing "id" contract exactly -- changing
	// that here would break every existing detail-page link). Never
	// serialized (unexported): purely an internal key for the batched
	// alert-severity lookup and the workspace-narrowed resource-ID
	// sets Overview derives below.
	resourceID uuid.UUID
}

// vmAvailability normalizes vms.connection_status's 7-value vocabulary
// (migration 014_ssh_connectivity.sql: NOT_CONFIGURED, READY, CONNECTING,
// CONNECTED, FAILED, HOST_KEY_UNKNOWN, HOST_KEY_CHANGED) into the
// dashboard's shared AVAILABLE/UNAVAILABLE/UNKNOWN vocabulary (decision
// #6): CONNECTED is the only success state; FAILED/HOST_KEY_* are
// definite, already-confirmed connection failures; NOT_CONFIGURED/READY/
// CONNECTING mean SSH connectivity has never been confirmed either way
// yet, so neither AVAILABLE nor UNAVAILABLE would be honest.
func vmAvailability(connectionStatus string) string {
	switch connectionStatus {
	case "CONNECTED":
		return "AVAILABLE"
	case "FAILED", "HOST_KEY_UNKNOWN", "HOST_KEY_CHANGED":
		return "UNAVAILABLE"
	default:
		return "UNKNOWN"
	}
}

// databaseAvailability normalizes ConnectionTestStatus's 7-value
// vocabulary (database_health.go: CONNECTED, AUTH_FAILED, TIMEOUT,
// REFUSED, TLS_ERROR, UNAVAILABLE, UNKNOWN) into the same shared
// vocabulary: CONNECTED is AVAILABLE, UNKNOWN (never tested) stays
// UNKNOWN, every other value is a definite reachability/auth failure and
// counts as UNAVAILABLE -- coarser than Health's own finer-grained split,
// by design (decision #6: one consistent column, not three).
func databaseAvailability(connectionStatus string) string {
	switch connectionStatus {
	case "CONNECTED":
		return "AVAILABLE"
	case "UNKNOWN", "":
		return "UNKNOWN"
	default:
		return "UNAVAILABLE"
	}
}

// objectStorageAvailability normalizes ObjectStorageConnectionStatus's
// 8-value vocabulary (object_storage_adapter.go: CONNECTED, AUTH_FAILED,
// ACCESS_DENIED, NOT_FOUND, TIMEOUT, TLS_ERROR, UNAVAILABLE, UNKNOWN) --
// same rule as databaseAvailability.
func objectStorageAvailability(connectionStatus string) string {
	switch connectionStatus {
	case "CONNECTED":
		return "AVAILABLE"
	case "UNKNOWN", "":
		return "UNKNOWN"
	default:
		return "UNAVAILABLE"
	}
}

// --- small map[string]any extraction helpers, for scopedDatabaseAccess/
// scopedObjectStorageAccess's untyped response rows (myaccess.go's own
// established shape -- reused verbatim rather than re-querying with typed
// rows a second time). ---

func mapString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func mapBool(m map[string]any, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func mapPermissions(m map[string]any) []string {
	if v, ok := m["permissions"].([]string); ok {
		return v
	}
	return []string{}
}

// mapWorkspaceIDAndName reads scopedDatabaseAccess/scopedObjectStorageAccess's
// "workspace_id" (*string) / "workspace_name" (plain string) pair into the
// DTO's plain string/string shape.
func mapWorkspaceIDAndName(m map[string]any) (workspaceID, workspaceName string) {
	if v, ok := m["workspace_id"].(*string); ok && v != nil {
		workspaceID = *v
	}
	workspaceName = mapString(m, "workspace_name")
	return
}

// resourceIDsOfType extracts the resourceID of every entry in list whose
// ResourceType matches resourceType (or every entry, if resourceType is
// ""), always as a non-nil (possibly zero-length) slice -- callers that
// pass this into a "resource_ids IS NULL = unrestricted" query must never
// accidentally pass nil here when the real answer is "authorized but
// zero", which would silently widen into "unrestricted."
func resourceIDsOfType(list []monitoringResourceDTO, resourceType string) []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(list))
	for _, res := range list {
		if resourceType == "" || res.ResourceType == resourceType {
			ids = append(ids, res.resourceID)
		}
	}
	return ids
}

// loadAuthorizedResources is the one shared merge function (plan decision
// #4): VMs via h.vms.List (identical to MyAccessHandler.authorizedVMs),
// Databases via scopedDatabaseAccess, Object Storage via
// scopedObjectStorageAccess -- the exact same building blocks
// GET /api/my-access already uses, so an unauthorized resource can never
// appear here for the same reason it can never appear there. VM health
// reuses services.DeriveDisplayHealth via one batched query
// (ListLatestMonitoringStatusByResourceIDs), mirroring vm_monitoring.go's
// GetCurrent single-VM pattern so the dashboard's VM health can never
// silently disagree with that VM's own detail page. ActiveAlertSeverity is
// attached via one batched WorstActiveAlertSeverityByResource query across
// every resource in the merged set. Returned sorted by Name for
// determinism (Resources/Overview both depend on stable ordering for
// pagination-free, deterministic responses).
func (h *MonitoringDashboardHandler) loadAuthorizedResources(r *http.Request, user services.AuthenticatedUser) ([]monitoringResourceDTO, error) {
	ctx := r.Context()
	resources := make([]monitoringResourceDTO, 0)

	// --- VMs ---
	vmItems, err := h.vms.List(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("load vms: %w", err)
	}
	vmResourceIDs := make([]uuid.UUID, 0, len(vmItems))
	for _, item := range vmItems {
		vmResourceIDs = append(vmResourceIDs, item.Detail.ResourceID)
	}
	vmStatuses, err := h.store.ListLatestMonitoringStatusByResourceIDs(ctx, vmResourceIDs)
	if err != nil {
		return nil, fmt.Errorf("load vm monitoring status: %w", err)
	}
	latestByVM := make(map[uuid.UUID]generated.ListLatestMonitoringStatusByResourceIDsRow, len(vmStatuses))
	for _, s := range vmStatuses {
		latestByVM[s.ResourceID] = s
	}
	for _, item := range vmItems {
		summary := toVMSummary(item.Detail, item.Permissions, item.Source)
		hasSnapshot := false
		storedHealth := services.HealthUnknown
		if s, ok := latestByVM[item.Detail.ResourceID]; ok {
			hasSnapshot = true
			storedHealth = services.HealthStatus(pgutil.TextOrEmpty(s.Status))
		}
		connectionHealthy := item.Detail.ConnectionStatus == "CONNECTED"
		health := services.DeriveDisplayHealth(hasSnapshot, connectionHealthy, storedHealth)
		resources = append(resources, monitoringResourceDTO{
			ID: summary.ID, resourceID: item.Detail.ResourceID, ResourceType: "VM", Name: summary.Name,
			WorkspaceID: summary.WorkspaceID, WorkspaceName: summary.Workspace,
			Health: string(health), Availability: vmAvailability(item.Detail.ConnectionStatus),
			ConnectionStatus: item.Detail.ConnectionStatus, MonitoringEnabled: item.Detail.MonitoringEnabled,
			Permissions: item.Permissions, AccessSource: string(item.Source),
			LastSeenAt: summary.LastSeenAt,
		})
	}

	// --- Databases ---
	dbRows, err := scopedDatabaseAccess(r, h.store, h.authz, h.databases, user)
	if err != nil {
		return nil, fmt.Errorf("load databases: %w", err)
	}
	for _, m := range dbRows {
		resourceID, perr := uuid.Parse(mapString(m, "resource_id"))
		if perr != nil {
			continue // defensive only -- scopedDatabaseAccess always sets a valid UUID string here
		}
		workspaceID, workspaceName := mapWorkspaceIDAndName(m)
		connectionStatus := mapString(m, "connection_status")
		var lastSeenAt *string
		if v, ok := m["last_metric_at"].(*string); ok {
			lastSeenAt = v
		}
		resources = append(resources, monitoringResourceDTO{
			ID: mapString(m, "id"), resourceID: resourceID, ResourceType: "DATABASE",
			Name: mapString(m, "name"), WorkspaceID: workspaceID, WorkspaceName: workspaceName,
			// Health is the row's own `health` field -- already computed
			// upstream by ComputeDatabaseHealth, in the shared
			// services.HealthStatus vocabulary -- never recomputed here.
			Health: mapString(m, "health"), Availability: databaseAvailability(connectionStatus),
			ConnectionStatus: connectionStatus, MonitoringEnabled: mapBool(m, "monitoring_enabled"),
			Permissions: mapPermissions(m), LastSeenAt: lastSeenAt,
		})
	}

	// --- Object Storage ---
	osRows, err := scopedObjectStorageAccess(r, h.store, h.authz, h.objectStorage, user)
	if err != nil {
		return nil, fmt.Errorf("load object storage: %w", err)
	}
	for _, m := range osRows {
		resourceID, perr := uuid.Parse(mapString(m, "resource_id"))
		if perr != nil {
			continue // defensive only -- scopedObjectStorageAccess always sets a valid UUID string here
		}
		workspaceID, workspaceName := mapWorkspaceIDAndName(m)
		connectionStatus := mapString(m, "connection_status")
		// "last_checked_at" is only present in the map at all when
		// latestMetricSummary found a real sample (never a fabricated
		// zero/empty string for a storage that's never been monitored).
		var lastSeenAt *string
		if v, ok := m["last_checked_at"].(string); ok {
			lastSeenAt = &v
		}
		resources = append(resources, monitoringResourceDTO{
			ID: mapString(m, "id"), resourceID: resourceID, ResourceType: "OBJECT_STORAGE",
			Name: mapString(m, "name"), WorkspaceID: workspaceID, WorkspaceName: workspaceName,
			Health: mapString(m, "health_status"), Availability: objectStorageAvailability(connectionStatus),
			ConnectionStatus: connectionStatus, MonitoringEnabled: mapBool(m, "monitoring_enabled"),
			Permissions: mapPermissions(m), LastSeenAt: lastSeenAt,
		})
	}

	// --- Active alert severity, batched across the whole merged set ---
	allIDs := make([]uuid.UUID, 0, len(resources))
	for _, res := range resources {
		allIDs = append(allIDs, res.resourceID)
	}
	severities, err := h.store.WorstActiveAlertSeverityByResource(ctx, allIDs)
	if err != nil {
		return nil, fmt.Errorf("load alert severities: %w", err)
	}
	severityByResource := make(map[uuid.UUID]string, len(severities))
	for _, s := range severities {
		severityByResource[s.ResourceID] = s.WorstSeverity
	}
	for i := range resources {
		if sev, ok := severityByResource[resources[i].resourceID]; ok {
			resources[i].ActiveAlertSeverity = &sev
		}
	}

	sort.Slice(resources, func(i, j int) bool { return resources[i].Name < resources[j].Name })
	return resources, nil
}

// healthBucket tallies a set of services.HealthStatus values into the
// {total, healthy, warning, critical, unknown, offline} shape Overview's
// VM/Database buckets both use.
type healthBucket struct {
	total, healthy, warning, critical, unknown, offline int
}

func (b *healthBucket) add(health string) {
	b.total++
	switch services.HealthStatus(health) {
	case services.HealthHealthy:
		b.healthy++
	case services.HealthWarning:
		b.warning++
	case services.HealthCritical:
		b.critical++
	case services.HealthOffline:
		b.offline++
	default:
		b.unknown++
	}
}

func (b healthBucket) toMap() map[string]any {
	return map[string]any{
		"total": b.total, "healthy": b.healthy, "warning": b.warning,
		"critical": b.critical, "unknown": b.unknown, "offline": b.offline,
	}
}

// Overview handles GET /api/monitoring/overview?workspace_id=:
// per-type health tallies (VM/Database from the merged DTO's own Health
// field; Object Storage reuses GetObjectStorageSummaryCounts verbatim,
// since it already correctly splits critical-vs-unavailable) plus Alerts/
// Recommendations/Docker summaries, all scoped to the caller's authorized
// resources -- narrowed further to one workspace when those query
// params are present (so a project-scoped Overview's alert/recommendation/
// docker counts only reflect that project's resources, never the caller's
// full set). The Docker bucket (Step 19 Phase 3) reuses the VM resource-ID
// subset of the exact same merged-and-possibly-narrowed `filtered` slice
// every other bucket below is computed from, rather than a fourth separate
// access-resolution call -- resourceIDsOfType always returns a real,
// non-nil (possibly zero-length) slice, so an Admin's unfiltered "every VM"
// set and a Member's/narrowed project's smaller set both flow through the
// same code path with no separate unrestricted-nil special case needed
// (unlike the Alerts/Object-Storage buckets above, GetDockerSummaryAcrossVMs
// has no other caller with its own nil-means-unrestricted convention to
// stay consistent with).
func (h *MonitoringDashboardHandler) Overview(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	ctx := r.Context()

	resources, err := h.loadAuthorizedResources(r, user)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load monitoring overview")
		return
	}

	q := r.URL.Query()
	workspaceFilter := strings.TrimSpace(q.Get("workspace_id"))
	scoped := workspaceFilter != ""

	filtered := resources
	if scoped {
		filtered = make([]monitoringResourceDTO, 0, len(resources))
		for _, res := range resources {
			if workspaceFilter != "" && res.WorkspaceID != workspaceFilter {
				continue
			}
			filtered = append(filtered, res)
		}
	}

	var vmBucket, dbBucket healthBucket
	for _, res := range filtered {
		switch res.ResourceType {
		case "VM":
			vmBucket.add(res.Health)
		case "DATABASE":
			dbBucket.add(res.Health)
		}
	}

	// Object Storage bucket: scoped exactly like ObjectStorageHandler.
	// Summary's own nil-for-admin/real-ids-for-member convention when
	// unfiltered; when a workspace filter is present, always an
	// explicit (possibly zero-length) slice derived from the filtered set
	// -- never nil, which the underlying query would otherwise read as
	// "unrestricted" and silently widen back out to every object storage
	// in the system.
	var osResourceIDs []uuid.UUID
	switch {
	case scoped:
		osResourceIDs = resourceIDsOfType(filtered, "OBJECT_STORAGE")
	case !user.IsAdmin():
		access, aerr := h.authz.GetUserObjectStorageAccess(ctx, user)
		if aerr != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
			return
		}
		osResourceIDs = make([]uuid.UUID, 0, len(access))
		for _, a := range access {
			osResourceIDs = append(osResourceIDs, a.ResourceID)
		}
	}
	osCounts, err := h.store.GetObjectStorageSummaryCounts(ctx, osResourceIDs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load object storage summary")
		return
	}

	// Alerts/Recommendations resource-ID scope: same nil-for-admin/real-
	// ids-for-member convention AlertsHandler.Summary/RecommendationHandler.
	// List already use (services.GetUserAlertAccessResourceIDs is never
	// called for an Admin -- the caller-side IsAdmin guard, not the
	// function itself, is what produces the nil "unrestricted" fast path),
	// narrowed to the workspace filter's own explicit ID set when
	// present, same non-nil-when-scoped rule as osResourceIDs above.
	var resourceIDs []uuid.UUID
	switch {
	case scoped:
		resourceIDs = resourceIDsOfType(filtered, "")
	case !user.IsAdmin():
		ids, aerr := services.GetUserAlertAccessResourceIDs(ctx, h.authz, user)
		if aerr != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
			return
		}
		resourceIDs = ids
	}

	alertRows, err := h.store.SummarizeAlertsByStatus(ctx, resourceIDs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to summarize alerts")
		return
	}
	// Mirrors AlertsHandler.Summary's own aggregation exactly, so the
	// dashboard's Alerts widget can never disagree with /api/alerts/summary
	// for the same caller/scope.
	alertSummary := map[string]any{"critical": 0, "warning": 0, "info": 0, "acknowledged": 0, "active": 0}
	for _, row := range alertRows {
		switch row.Status {
		case "ACTIVE":
			alertSummary["active"] = alertSummary["active"].(int) + int(row.Total)
			switch row.Severity {
			case "CRITICAL":
				alertSummary["critical"] = alertSummary["critical"].(int) + int(row.Total)
			case "WARNING":
				alertSummary["warning"] = alertSummary["warning"].(int) + int(row.Total)
			case "INFO":
				alertSummary["info"] = alertSummary["info"].(int) + int(row.Total)
			}
		case "ACKNOWLEDGED":
			alertSummary["acknowledged"] = alertSummary["acknowledged"].(int) + int(row.Total)
		}
	}
	resolvedToday, _ := h.store.CountResolvedToday(ctx, resourceIDs)
	alertSummary["resolved_today"] = resolvedToday

	recCounts, err := h.store.GetRecommendationSummaryCounts(ctx, resourceIDs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load recommendation summary")
		return
	}

	// Docker bucket (Step 19 Phase 3): the VM-only subset of `filtered`
	// (which equals the caller's full authorized set when unscoped) --
	// always an explicit, non-nil slice, so a zero-VM Admin/project never
	// silently reads as "unrestricted" and widens back out.
	dockerVMResourceIDs := resourceIDsOfType(filtered, "VM")
	dockerSummary, err := h.store.GetDockerSummaryAcrossVMs(ctx, dockerVMResourceIDs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load docker summary")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"vms":       vmBucket.toMap(),
		"databases": dbBucket.toMap(),
		"object_storage": map[string]any{
			"total": osCounts.Total, "healthy": osCounts.Healthy, "warning": osCounts.Warning,
			"critical": osCounts.Critical, "unavailable": osCounts.Unavailable,
		},
		"alerts": alertSummary,
		"recommendations": map[string]any{
			"total": recCounts.Total, "new": recCounts.New, "acknowledged": recCounts.Acknowledged,
			"dismissed": recCounts.Dismissed, "resolved": recCounts.Resolved,
			"open_critical": recCounts.OpenCritical, "open_high": recCounts.OpenHigh,
			"open_medium": recCounts.OpenMedium, "open_low": recCounts.OpenLow,
		},
		"docker": map[string]any{
			"hosts": dockerSummary.DockerHosts, "containers_total": dockerSummary.ContainersTotal,
			"containers_running": dockerSummary.ContainersRunning, "containers_stopped": dockerSummary.ContainersStopped,
			"containers_unhealthy": dockerSummary.ContainersUnhealthy, "images_total": dockerSummary.ImagesTotal,
		},
	})
}

// Resources handles GET /api/monitoring/resources?resource_type=&
// workspace_id=&health=&alert_severity=&search=: the unified,
// unpaginated (matches every existing per-type List endpoint's own
// convention) resource table, filtered entirely in Go over the merged,
// already-authorization-scoped slice (plan decision #4) -- never a new
// WHERE clause pushed into three different SQL query families for one
// endpoint's filter UI. Because loadAuthorizedResources already excludes
// every unauthorized resource before any filter below ever runs, an
// unauthorized resource's name can never leak into a `search` match
// either.
func (h *MonitoringDashboardHandler) Resources(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	resources, err := h.loadAuthorizedResources(r, user)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load monitoring resources")
		return
	}

	q := r.URL.Query()
	resourceType := strings.ToUpper(strings.TrimSpace(q.Get("resource_type")))
	workspaceFilter := strings.TrimSpace(q.Get("workspace_id"))
	healthFilter := strings.ToUpper(strings.TrimSpace(q.Get("health")))
	severityFilter := strings.ToUpper(strings.TrimSpace(q.Get("alert_severity")))
	search := strings.ToLower(strings.TrimSpace(q.Get("search")))

	filtered := make([]monitoringResourceDTO, 0, len(resources))
	for _, res := range resources {
		if resourceType != "" && res.ResourceType != resourceType {
			continue
		}
		if workspaceFilter != "" && res.WorkspaceID != workspaceFilter {
			continue
		}
		if healthFilter != "" && res.Health != healthFilter {
			continue
		}
		if severityFilter != "" && (res.ActiveAlertSeverity == nil || *res.ActiveAlertSeverity != severityFilter) {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(res.Name), search) {
			continue
		}
		filtered = append(filtered, res)
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"resources": filtered, "total": len(filtered)})
}

// timelineFetchCap bounds how many of the caller's most relevant alerts/
// recommendations Timeline reads before exploding each into its synthetic
// events -- 30 of each gives up to 30*3+30*2=150 raw events, comfortable
// headroom over the default limit (50) and most of the way to the 200 cap
// Timeline's own limit= param shares with parsePagination's usual
// convention (Timeline can never actually return more than 150 regardless
// of a larger requested limit, since that's the real ceiling on distinct
// lifecycle timestamps 30+30 source rows can produce -- an accepted,
// documented tradeoff of composing the timeline from bounded recent-
// activity queries rather than a dedicated paginated events table, plan
// decision #7).
const timelineFetchCap = 30

// timelineEventDTO is one synthetic event Timeline emits, composed from an
// alert's or recommendation's own lifecycle timestamps (plan decision #7)
// -- never a new audit-log row. Only ever constructed by
// alertTimelineEvents/recommendationTimelineEvents below, which skip any
// timestamp column that isn't actually set, so a never-acknowledged/
// never-resolved alert or never-resolved recommendation contributes fewer
// events, never a fabricated one at a placeholder time.
type timelineEventDTO struct {
	Timestamp    string `json:"timestamp"`
	Type         string `json:"type"`
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	ResourceName string `json:"resource_name"`
	Description  string `json:"description"`
	Severity     string `json:"severity"`

	// sortTime is the same instant Timestamp renders, kept as a real
	// time.Time (rather than re-parsing the formatted string) so
	// descending sort is a correct chronological comparison -- never
	// serialized.
	sortTime time.Time
}

// alertTimelineEvents explodes one alert row into up to 3 synthetic
// events -- ALERT_TRIGGERED (first_seen_at), ALERT_ACKNOWLEDGED
// (acknowledged_at), ALERT_RESOLVED (resolved_at) -- emitting only the
// ones whose backing column is actually set (pgutil.TimePtr returns nil
// for an unset pgtype.Timestamptz), per Timeline's core constraint: a
// null acknowledged_at/resolved_at means "don't emit that event," never
// "use some placeholder time."
func alertTimelineEvents(a generated.ListAlertsFilteredRow) []timelineEventDTO {
	events := make([]timelineEventDTO, 0, 3)
	resourceID := a.ResourceID.String()
	add := func(ts *time.Time, eventType string) {
		if ts == nil {
			return
		}
		events = append(events, timelineEventDTO{
			Timestamp: ts.Format(time.RFC3339), Type: eventType, sortTime: *ts,
			ResourceID: resourceID, ResourceType: a.ResourceType, ResourceName: a.ResourceName,
			Description: a.Title, Severity: a.Severity,
		})
	}
	add(pgutil.TimePtr(a.FirstSeenAt), "ALERT_TRIGGERED")
	add(pgutil.TimePtr(a.AcknowledgedAt), "ALERT_ACKNOWLEDGED")
	add(pgutil.TimePtr(a.ResolvedAt), "ALERT_RESOLVED")
	return events
}

// recommendationTimelineEvents is alertTimelineEvents's Recommendations
// counterpart -- up to 2 synthetic events (RECOMMENDATION_DETECTED/
// RECOMMENDATION_RESOLVED), same non-null-only rule.
func recommendationTimelineEvents(rec generated.ListRecommendationsFilteredRow) []timelineEventDTO {
	events := make([]timelineEventDTO, 0, 2)
	resourceID := rec.ResourceID.String()
	add := func(ts *time.Time, eventType string) {
		if ts == nil {
			return
		}
		events = append(events, timelineEventDTO{
			Timestamp: ts.Format(time.RFC3339), Type: eventType, sortTime: *ts,
			ResourceID: resourceID, ResourceType: rec.ResourceType, ResourceName: rec.ResourceName,
			Description: rec.Title, Severity: rec.Severity,
		})
	}
	add(pgutil.TimePtr(rec.DetectedAt), "RECOMMENDATION_DETECTED")
	add(pgutil.TimePtr(rec.ResolvedAt), "RECOMMENDATION_RESOLVED")
	return events
}

// Timeline handles GET /api/monitoring/timeline?workspace_id=&
// limit=: a composed "recent events" feed built from Alerts' and
// Recommendations' own lifecycle timestamps rather than a new audit-log
// endpoint (plan decision #7 -- audit_logs mixes security and operational
// events with no category column, and a correctly-scoped audit endpoint is
// a standalone feature in its own right). Scoped identically to Overview's
// own resourceIDs computation (loadAuthorizedResources, then the same
// workspace narrowing, then the same nil-for-admin-unscoped/
// GetUserAlertAccessResourceIDs-for-member-unscoped/resourceIDsOfType-when-
// scoped convention) -- duplicated here rather than factored into a shared
// helper so Overview's own code path is untouched by this feature, per the
// "purely additive" constraint. limit defaults to 50, capped at 200
// (parsePagination's own existing default/max convention); the response's
// "total" is the event count *before* limit truncates it, mirroring every
// other List endpoint's own separately-reported total/page-size split.
func (h *MonitoringDashboardHandler) Timeline(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	ctx := r.Context()

	resources, err := h.loadAuthorizedResources(r, user)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load monitoring timeline")
		return
	}

	q := r.URL.Query()
	workspaceFilter := strings.TrimSpace(q.Get("workspace_id"))
	scoped := workspaceFilter != ""

	filtered := resources
	if scoped {
		filtered = make([]monitoringResourceDTO, 0, len(resources))
		for _, res := range resources {
			if workspaceFilter != "" && res.WorkspaceID != workspaceFilter {
				continue
			}
			filtered = append(filtered, res)
		}
	}

	// Alerts/Recommendations resource-ID scope: identical to Overview's own
	// resourceIDs computation.
	var resourceIDs []uuid.UUID
	switch {
	case scoped:
		resourceIDs = resourceIDsOfType(filtered, "")
	case !user.IsAdmin():
		ids, aerr := services.GetUserAlertAccessResourceIDs(ctx, h.authz, user)
		if aerr != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
			return
		}
		resourceIDs = ids
	}

	limit, _ := parsePagination(r, 50, 200)

	alertRows, err := h.store.ListAlertsFiltered(ctx, generated.ListAlertsFilteredParams{Limit: timelineFetchCap, ResourceIds: resourceIDs})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load timeline alerts")
		return
	}
	recRows, err := h.store.ListRecommendationsFiltered(ctx, generated.ListRecommendationsFilteredParams{Limit: timelineFetchCap, ResourceIds: resourceIDs})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load timeline recommendations")
		return
	}

	events := make([]timelineEventDTO, 0, len(alertRows)*3+len(recRows)*2)
	for _, a := range alertRows {
		events = append(events, alertTimelineEvents(a)...)
	}
	for _, rec := range recRows {
		events = append(events, recommendationTimelineEvents(rec)...)
	}

	sort.Slice(events, func(i, j int) bool { return events[i].sortTime.After(events[j].sortTime) })

	total := len(events)
	if int32(len(events)) > limit {
		events = events[:limit]
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"events": events, "total": total})
}
