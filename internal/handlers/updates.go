package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// UpdatesHandler implements the Step 9 Update Center API: OS/kernel/
// reboot detection (read-only, backend-driven), and update planning
// (admin-only, never executing anything -- see UpdatePlanService's own
// doc comment). Every VM-scoped GET checks vm.view individually (404,
// not 403, on failure, matching every VM-scoped endpoint since Step 3);
// every plan endpoint is admin-only end to end (spec §43's "Keep update
// planning Admin-only"), enforced at the router via requireAdmin.
type UpdatesHandler struct {
	store            *repository.Store
	authz            *services.AuthorizationService
	plans            *services.UpdatePlanService
	packageScheduler *services.PackageScanScheduler
	osUpdates        *services.OSUpdateService
	commandBuilders  *services.UpdateCommandBuilderFactory
	audit            *services.AuditService
}

// NewUpdatesHandler creates an UpdatesHandler.
func NewUpdatesHandler(
	store *repository.Store, authz *services.AuthorizationService, plans *services.UpdatePlanService,
	packageScheduler *services.PackageScanScheduler, osUpdates *services.OSUpdateService, audit *services.AuditService,
) *UpdatesHandler {
	return &UpdatesHandler{
		store: store, authz: authz, plans: plans, packageScheduler: packageScheduler, osUpdates: osUpdates,
		commandBuilders: services.NewUpdateCommandBuilderFactory(), audit: audit,
	}
}

// authorizeVMView resolves :id and checks vm.view, returning the VM's
// resource ID and the vms row itself.
func (h *UpdatesHandler) authorizeVMView(w http.ResponseWriter, r *http.Request) (resourceID uuid.UUID, vm generated.Vm, ok bool) {
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
	allowed, err := h.authz.CanAccessVMAny(r.Context(), user, resourceID, services.PermVMView, services.PermVMUpdates)
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

// --- DTOs ---

type osUpdateDTO struct {
	Current        string  `json:"current,omitempty"`
	Available      string  `json:"available,omitempty"`
	Status         string  `json:"status"`
	UpdateType     string  `json:"update_type,omitempty"`
	ReleaseChannel string  `json:"release_channel,omitempty"`
	DetectedAt     *string `json:"detected_at,omitempty"`
}

func toOSUpdateDTO(row generated.OsUpdate) osUpdateDTO {
	return osUpdateDTO{
		Current: row.CurrentVersion, Available: pgutil.TextOrEmpty(row.AvailableVersion), Status: row.Status,
		UpdateType: pgutil.TextOrEmpty(row.UpdateType), ReleaseChannel: pgutil.TextOrEmpty(row.ReleaseChannel),
		DetectedAt: formatTimestamptz(row.DetectedAt),
	}
}

type kernelDTO struct {
	Running        string `json:"running,omitempty"`
	Available      string `json:"available,omitempty"`
	RebootRequired bool   `json:"reboot_required"`
	RebootStatus   string `json:"reboot_status"`
	RebootReason   string `json:"reboot_reason,omitempty"`
}

func toKernelDTO(vm generated.Vm) kernelDTO {
	status := pgutil.TextOrEmpty(vm.RebootStatus)
	if status == "" {
		status = "UNKNOWN"
	}
	return kernelDTO{
		Running: pgutil.TextOrEmpty(vm.KernelVersion), Available: pgutil.TextOrEmpty(vm.KernelAvailable),
		RebootRequired: status == "REQUIRED", RebootStatus: status, RebootReason: pgutil.TextOrEmpty(vm.RebootReason),
	}
}

// --- Cross-VM update summary (spec §14/§44/§46) ---

type vmUpdateSummaryDTO struct {
	VMID                string `json:"vm_id"`
	VMName              string `json:"vm_name"`
	OSStatus            string `json:"os_status"`
	PackageUpdateCount  int64  `json:"package_update_count"`
	SecurityUpdateCount int64  `json:"security_update_count"`
	RebootStatus        string `json:"reboot_status"`
}

type globalUpdateTotalsDTO struct {
	VMsWithUpdates  int   `json:"vms_with_updates"`
	SecurityUpdates int64 `json:"security_updates"`
	PackageUpdates  int64 `json:"package_updates"`
	OSUpdates       int   `json:"os_updates"`
	RebootsRequired int   `json:"reboots_required"`
}

// List handles GET /api/updates. ADMIN: every VM. MEMBER: only VMs
// they're authorized on, and the "totals" cards are computed from that
// same restricted set -- never a separately-fetched global count (spec
// §46's explicit "do not leak total global VM update count").
func (h *UpdatesHandler) List(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var resourceIDs []uuid.UUID
	if !user.IsAdmin() {
		access, err := h.authz.GetUserVMAccess(r.Context(), user)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
			return
		}
		resourceIDs = make([]uuid.UUID, 0, len(access))
		for _, a := range access {
			resourceIDs = append(resourceIDs, a.ResourceID)
		}
	}

	rows, err := h.store.ListVMUpdateSummaries(r.Context(), resourceIDs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load update summaries")
		return
	}

	items := make([]vmUpdateSummaryDTO, 0, len(rows))
	totals := globalUpdateTotalsDTO{}
	for _, row := range rows {
		osStatus := pgutil.TextOrEmpty(row.OsStatus)
		rebootStatus := pgutil.TextOrEmpty(row.RebootStatus)
		items = append(items, vmUpdateSummaryDTO{
			VMID: row.ResourceID.String(), VMName: row.VmName, OSStatus: osStatus,
			PackageUpdateCount: row.PackageUpdateCount, SecurityUpdateCount: row.SecurityUpdateCount,
			RebootStatus: rebootStatus,
		})
		if row.PackageUpdateCount > 0 || osStatus == "UPDATE_AVAILABLE" {
			totals.VMsWithUpdates++
		}
		totals.SecurityUpdates += row.SecurityUpdateCount
		totals.PackageUpdates += row.PackageUpdateCount
		if osStatus == "UPDATE_AVAILABLE" {
			totals.OSUpdates++
		}
		if rebootStatus == "REQUIRED" {
			totals.RebootsRequired++
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"vms": items, "totals": totals})
}

// --- Per-VM update detail ---

// GetVMUpdates handles GET /api/vms/:id/updates.
func (h *UpdatesHandler) GetVMUpdates(w http.ResponseWriter, r *http.Request) {
	_, vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}

	resp := map[string]any{
		"os":     osUpdateDTO{Status: "UNKNOWN"},
		"kernel": toKernelDTO(vm),
	}
	if osUpd, err := h.store.GetOSUpdateByVM(r.Context(), vm.ID); err == nil {
		resp["os"] = toOSUpdateDTO(osUpd)
	}

	updates, err := h.store.ListPackageUpdatesByVM(r.Context(), generated.ListPackageUpdatesByVMParams{VmID: vm.ID, Limit: 500})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load package updates")
		return
	}
	items := make([]packageUpdateDTO, 0, len(updates))
	for _, u := range updates {
		items = append(items, toPackageUpdateDTO(u))
	}
	resp["packages"] = items
	resp["package_count"] = len(items)

	httpx.WriteJSON(w, http.StatusOK, resp)
}

// GetVMUpdatesSummary handles GET /api/vms/:id/updates/summary -- spec
// §13's exact response shape.
func (h *UpdatesHandler) GetVMUpdatesSummary(w http.ResponseWriter, r *http.Request) {
	_, vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}

	osResp := map[string]any{"status": "UNKNOWN"}
	if osUpd, err := h.store.GetOSUpdateByVM(r.Context(), vm.ID); err == nil {
		osResp["current"] = osUpd.CurrentVersion
		osResp["status"] = osUpd.Status
		if av := pgutil.TextOrEmpty(osUpd.AvailableVersion); av != "" {
			osResp["available"] = av
		}
	}

	pkgSummary, err := h.store.GetPackageSummaryByVM(r.Context(), vm.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load package summary")
		return
	}

	kernelResp := map[string]any{"reboot_required": pgutil.TextOrEmpty(vm.RebootStatus) == "REQUIRED"}
	if running := pgutil.TextOrEmpty(vm.KernelVersion); running != "" {
		kernelResp["running"] = running
	}
	if available := pgutil.TextOrEmpty(vm.KernelAvailable); available != "" {
		kernelResp["available"] = available
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"os": osResp,
		"packages": map[string]any{
			"total_updates": pkgSummary.UpdatesAvailable, "security_updates": pkgSummary.SecurityUpdates,
		},
		"kernel": kernelResp,
	})
}

// GetVMUpdatesSecurity handles GET /api/vms/:id/updates/security.
func (h *UpdatesHandler) GetVMUpdatesSecurity(w http.ResponseWriter, r *http.Request) {
	_, vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	updates, err := h.store.ListPackageUpdatesByVM(r.Context(), generated.ListPackageUpdatesByVMParams{
		VmID: vm.ID, SecurityOnly: pgutil.Bool(true), Limit: 500,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load security updates")
		return
	}
	items := make([]packageUpdateDTO, 0, len(updates))
	for _, u := range updates {
		items = append(items, toPackageUpdateDTO(u))
	}
	severity, err := h.store.GetSecurityUpdateSeverityCounts(r.Context(), vm.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load severity counts")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"updates": items, "total": len(items),
		"severity": map[string]any{
			"critical": severity.Critical, "high": severity.High, "medium": severity.Medium,
			"low": severity.Low, "unknown": severity.Unknown,
		},
	})
}

// GetVMUpdatesKernel handles GET /api/vms/:id/updates/kernel.
func (h *UpdatesHandler) GetVMUpdatesKernel(w http.ResponseWriter, r *http.Request) {
	_, vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toKernelDTO(vm))
}

// toPackageUpdateDTO mirrors PackageHandler.ListUpdates' row->DTO
// conversion exactly (packageUpdateDTO is the same type, defined in
// vm_packages.go) -- Update Center never duplicates package-update data,
// only re-renders what Step 7 already computed (spec §8).
func toPackageUpdateDTO(row generated.ListPackageUpdatesByVMRow) packageUpdateDTO {
	return packageUpdateDTO{
		ID: row.ID.String(), PackageID: row.PackageID.String(), PackageName: row.PackageName,
		CurrentVersion: row.CurrentVersion, AvailableVersion: row.AvailableVersion,
		Architecture: pgutil.TextOrEmpty(row.Architecture), Release: pgutil.TextOrEmpty(row.Release),
		Severity: row.Severity, IsSecurityUpdate: row.IsSecurityUpdate, SecurityStatus: row.SecurityStatus,
		RecommendationStatus: row.RecommendationStatus, DetectedAt: row.DetectedAt.Time.Format(time.RFC3339),
	}
}

// --- Prechecks & refresh ---

type precheckItemDTO struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

func toPrecheckReportDTO(report services.PrecheckReport) map[string]any {
	items := make([]precheckItemDTO, 0, len(report.Items))
	for _, item := range report.Items {
		items = append(items, precheckItemDTO{Name: item.Name, Status: string(item.Status), Message: item.Message})
	}
	return map[string]any{"items": items, "all_passed": report.AllPassed}
}

// RunPrecheck handles POST /api/vms/:id/updates/precheck (admin-only).
func (h *UpdatesHandler) RunPrecheck(w http.ResponseWriter, r *http.Request) {
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	if _, err := h.store.GetVMResourceByID(r.Context(), resourceID); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	report, err := h.plans.RunVMPrecheck(r.Context(), resourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to run prechecks")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toPrecheckReportDTO(report))
}

type refreshResultDTO struct {
	Status       string `json:"status"`
	PackageCount int    `json:"package_count"`
	UpdateCount  int    `json:"update_count"`
	OSStatus     string `json:"os_status,omitempty"`
	RebootStatus string `json:"reboot_status,omitempty"`
	ErrorSummary string `json:"error_summary,omitempty"`
}

// RefreshUpdates handles POST /api/vms/:id/updates/refresh (admin-only,
// spec §47/§48/§49): package metadata refresh -> package scan -> OS
// update detection -> kernel detection -> reboot detection, all
// re-detection, never installation. The package half is rate-limited/
// overlap-guarded by PackageScanScheduler.ScanNow (Step 7's existing
// infrastructure, spec §67's "reuse the scheduler"); the OS-update half
// only runs once that guard has already been passed for this VM,
// naturally serializing the two.
func (h *UpdatesHandler) RefreshUpdates(w http.ResponseWriter, r *http.Request) {
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
		UserID: &actor.ID, Action: services.AuditUpdateScanStarted, ResourceType: "VM", ResourceID: &resourceID,
	})

	pkgResult, err := h.packageScheduler.ScanNow(r.Context(), resourceID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrPackageScanInProgress), errors.Is(err, services.ErrPackageScanRateLimited):
			httpx.WriteError(w, http.StatusTooManyRequests, err.Error())
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "refresh failed")
		}
		return
	}

	osResult, osErr := h.osUpdates.Scan(r.Context(), resourceID)

	action := services.AuditUpdateScanCompleted
	if pkgResult.Status == "FAILED" || osErr != nil || osResult.Status == "FAILED" {
		action = services.AuditUpdateScanFailed
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: action, ResourceType: "VM", ResourceID: &resourceID,
		Metadata: map[string]any{
			"package_status": pkgResult.Status, "update_count": pkgResult.UpdateCount,
			"os_status": osResult.OSStatus, "reboot_status": osResult.RebootStatus,
		},
	})

	resp := refreshResultDTO{
		Status: pkgResult.Status, PackageCount: pkgResult.PackageCount, UpdateCount: pkgResult.UpdateCount,
		OSStatus: osResult.OSStatus, RebootStatus: osResult.RebootStatus,
	}
	if pkgResult.ErrorSummary != "" {
		resp.ErrorSummary = pkgResult.ErrorSummary
	} else if osResult.ErrorSummary != "" {
		resp.ErrorSummary = osResult.ErrorSummary
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// --- Update plans (spec §22-28, admin-only end to end) ---

type updatePlanDTO struct {
	ID        string  `json:"id"`
	VMID      string  `json:"vm_id,omitempty"`
	VMName    string  `json:"vm_name,omitempty"`
	CreatedBy *string `json:"created_by,omitempty"`
	Status    string  `json:"status"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
}

func toUpdatePlanDTO(plan generated.UpdatePlan) updatePlanDTO {
	return updatePlanDTO{
		ID: plan.ID.String(), Status: plan.Status,
		CreatedAt: plan.CreatedAt.Time.Format(time.RFC3339), UpdatedAt: plan.UpdatedAt.Time.Format(time.RFC3339),
	}
}

type updatePlanItemDTO struct {
	ID             string `json:"id"`
	PackageID      string `json:"package_id"`
	PackageName    string `json:"package_name"`
	CurrentVersion string `json:"current_version"`
	TargetVersion  string `json:"target_version"`
	UpdateType     string `json:"update_type"`
	SecurityUpdate bool   `json:"security_update"`
	Severity       string `json:"severity"`
}

func toUpdatePlanItemDTO(item generated.UpdatePlanItem) updatePlanItemDTO {
	return updatePlanItemDTO{
		ID: item.ID.String(), PackageID: item.PackageID.String(), PackageName: item.PackageName,
		CurrentVersion: item.CurrentVersion, TargetVersion: item.TargetVersion,
		UpdateType: item.UpdateType, SecurityUpdate: item.SecurityUpdate, Severity: item.Severity,
	}
}

// planItemsSummary computes the small "N packages selected / security
// updates / kernel / reboot" summary spec §22/§41 show above the command
// preview -- reboot is true whenever any KERNEL-type item is present, or
// the VM's own currently-known reboot_status is already REQUIRED.
func planItemsSummary(items []generated.UpdatePlanItem, vmRebootRequired bool) map[string]any {
	securityCount, kernelCount := 0, 0
	for _, item := range items {
		if item.SecurityUpdate {
			securityCount++
		}
		if item.UpdateType == "KERNEL" {
			kernelCount++
		}
	}
	return map[string]any{
		"selected_count": len(items), "security_update_count": securityCount, "kernel_update_count": kernelCount,
		"reboot_required": kernelCount > 0 || vmRebootRequired,
	}
}

type createUpdatePlanRequest struct {
	Items []struct {
		PackageID     string `json:"package_id"`
		TargetVersion string `json:"target_version"`
	} `json:"items"`
}

// CreatePlan handles POST /api/vms/:id/update-plans (admin-only).
func (h *UpdatesHandler) CreatePlan(w http.ResponseWriter, r *http.Request) {
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	if _, err := h.store.GetVMResourceByID(r.Context(), resourceID); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}

	var req createUpdatePlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Items) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "at least one package must be selected")
		return
	}
	selections := make([]services.PlanItemSelection, 0, len(req.Items))
	for _, item := range req.Items {
		pkgID, err := uuid.Parse(item.PackageID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid package_id")
			return
		}
		selections = append(selections, services.PlanItemSelection{PackageID: pkgID, TargetVersion: item.TargetVersion})
	}

	actor, _ := services.UserFromContext(r.Context())
	plan, items, err := h.plans.CreatePlan(r.Context(), resourceID, actor.ID, selections)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrUpdatePlanNoItems), errors.Is(err, services.ErrUpdatePlanDuplicateItem),
			errors.Is(err, services.ErrUpdatePlanVMInactive), errors.Is(err, services.ErrUpdatePlanPackageNotFound),
			errors.Is(err, services.ErrUpdatePlanUpdateUnavailable):
			httpx.WriteError(w, http.StatusBadRequest, err.Error())
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "failed to create update plan")
		}
		return
	}

	securityCount := 0
	for _, item := range items {
		if item.SecurityUpdate {
			securityCount++
		}
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditUpdatePlanCreated, ResourceType: "VM", ResourceID: &resourceID,
		Metadata: map[string]any{
			"update_plan_id": plan.ID, "selected_count": len(items),
			"security_update_count": securityCount, "plan_status": plan.Status,
		},
	})

	itemDTOs := make([]updatePlanItemDTO, 0, len(items))
	for _, item := range items {
		itemDTOs = append(itemDTOs, toUpdatePlanItemDTO(item))
	}
	resp := map[string]any{"plan": toUpdatePlanDTO(plan), "items": itemDTOs}
	for k, v := range planItemsSummary(items, false) {
		resp[k] = v
	}
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

// GetPlan handles GET /api/update-plans/:id (admin-only).
func (h *UpdatesHandler) GetPlan(w http.ResponseWriter, r *http.Request) {
	planID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "update plan not found")
		return
	}
	detail, items, err := h.plans.GetPlanDetail(r.Context(), planID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "update plan not found")
		return
	}
	vm, err := h.store.GetVMByID(r.Context(), detail.VmID)
	rebootRequired := err == nil && pgutil.TextOrEmpty(vm.RebootStatus) == "REQUIRED"

	itemDTOs := make([]updatePlanItemDTO, 0, len(items))
	for _, item := range items {
		itemDTOs = append(itemDTOs, toUpdatePlanItemDTO(item))
	}

	planDTO := updatePlanDTO{
		ID: detail.ID.String(), VMID: detail.VmResourceID.String(), VMName: detail.VmName,
		Status: detail.Status, CreatedAt: detail.CreatedAt.Time.Format(time.RFC3339), UpdatedAt: detail.UpdatedAt.Time.Format(time.RFC3339),
	}
	if name := pgutil.TextOrEmpty(detail.CreatedByName); name != "" {
		planDTO.CreatedBy = &name
	}

	resp := map[string]any{"plan": planDTO, "items": itemDTOs}
	for k, v := range planItemsSummary(items, rebootRequired) {
		resp[k] = v
	}

	// Command preview (spec §29/§31/§32/§33) -- backend-generated only,
	// never accepted from a request. Absent entirely if the VM's package
	// manager is unsupported/undetected.
	if err == nil {
		pmType := services.PackageManagerType(pgutil.TextOrEmpty(vm.PackageManager))
		if builder := h.commandBuilders.New(pmType); builder != nil {
			names := make([]string, 0, len(items))
			kernelNames := make([]string, 0)
			for _, item := range items {
				names = append(names, item.PackageName)
				if item.UpdateType == "KERNEL" {
					kernelNames = append(kernelNames, item.PackageName)
				}
			}
			if cmd := builder.BuildPackageUpdateCommand(names); cmd != "" {
				resp["proposed_command"] = cmd
			}
			if len(kernelNames) > 0 {
				resp["kernel_command"] = builder.BuildKernelUpdateCommand(kernelNames)
			}
			if osCmd, ok := builder.BuildOSReleaseCommand(pgutil.TextOrEmpty(vm.DistributionID)); ok {
				resp["os_release_command"] = map[string]any{"command": osCmd, "high_risk": true}
			}
		}
	}
	resp["executed"] = false

	httpx.WriteJSON(w, http.StatusOK, resp)
}

// ListPlansForVM handles GET /api/vms/:id/update-plans (admin-only).
func (h *UpdatesHandler) ListPlansForVM(w http.ResponseWriter, r *http.Request) {
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	vm, err := h.store.GetVMByResourceID(r.Context(), resourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	plans, err := h.store.ListUpdatePlansByVM(r.Context(), vm.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load update plans")
		return
	}
	items := make([]updatePlanDTO, 0, len(plans))
	for _, p := range plans {
		items = append(items, toUpdatePlanDTO(p))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"plans": items})
}

// ValidatePlan handles POST /api/update-plans/:id/validate (admin-only).
// Never mutates plan status -- a pure diagnostic report.
func (h *UpdatesHandler) ValidatePlan(w http.ResponseWriter, r *http.Request) {
	planID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "update plan not found")
		return
	}
	if _, err := h.store.GetUpdatePlanByID(r.Context(), planID); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "update plan not found")
		return
	}

	result, err := h.plans.ValidatePlan(r.Context(), planID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to validate update plan")
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditUpdatePlanValidated, ResourceType: "VM", ResourceID: h.planVMResourceID(r, planID),
		Metadata: map[string]any{"update_plan_id": planID, "all_passed": result.Report.AllPassed, "stale": result.Stale},
	})

	resp := toPrecheckReportDTO(result.Report)
	resp["stale"] = result.Stale
	if len(result.StaleItems) > 0 {
		resp["stale_items"] = result.StaleItems
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// ApprovePlan handles POST /api/update-plans/:id/approve (admin-only,
// spec #42's exact contract: "only moves DRAFT -> READY. It must NOT
// execute the command.").
func (h *UpdatesHandler) ApprovePlan(w http.ResponseWriter, r *http.Request) {
	planID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "update plan not found")
		return
	}

	plan, result, err := h.plans.ApprovePlan(r.Context(), planID)
	if err != nil {
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			httpx.WriteError(w, http.StatusNotFound, "update plan not found")
		case errors.Is(err, services.ErrUpdatePlanNotDraft):
			httpx.WriteError(w, http.StatusConflict, err.Error())
		case errors.Is(err, services.ErrUpdatePlanChecksFailed):
			httpx.WriteJSON(w, http.StatusConflict, map[string]any{
				"error": "plan failed one or more required prechecks", "precheck": toPrecheckReportDTO(result.Report),
			})
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "failed to approve update plan")
		}
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditUpdatePlanApproved, ResourceType: "VM", ResourceID: h.planVMResourceID(r, plan.ID),
		Metadata: map[string]any{"update_plan_id": plan.ID, "plan_status": plan.Status},
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"plan": toUpdatePlanDTO(plan), "message": "Plan approved. Use POST /api/update-plans/:id/execute with explicit confirmation to run it.",
	})
}

// CancelPlan handles POST /api/update-plans/:id/cancel (admin-only).
func (h *UpdatesHandler) CancelPlan(w http.ResponseWriter, r *http.Request) {
	planID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "update plan not found")
		return
	}
	plan, err := h.plans.CancelPlan(r.Context(), planID)
	if err != nil {
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			httpx.WriteError(w, http.StatusNotFound, "update plan not found")
		case errors.Is(err, services.ErrUpdatePlanTerminal), errors.Is(err, services.ErrUpdatePlanExecuting):
			httpx.WriteError(w, http.StatusConflict, err.Error())
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "failed to cancel update plan")
		}
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditUpdatePlanCancelled, ResourceType: "VM", ResourceID: h.planVMResourceID(r, plan.ID),
		Metadata: map[string]any{"update_plan_id": plan.ID},
	})

	httpx.WriteJSON(w, http.StatusOK, toUpdatePlanDTO(plan))
}

// planVMResourceID resolves the resources.id a plan belongs to, for
// audit logging -- best-effort: a lookup failure simply omits the
// resource link rather than failing the whole request (the audit event
// itself still records the update_plan_id in its metadata either way).
func (h *UpdatesHandler) planVMResourceID(r *http.Request, planID uuid.UUID) *uuid.UUID {
	detail, err := h.store.GetUpdatePlanDetail(r.Context(), planID)
	if err != nil {
		return nil
	}
	id := detail.VmResourceID
	return &id
}
