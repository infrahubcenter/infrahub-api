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

const (
	defaultPackagePageSize = 50
	maxPackagePageSize     = 200
)

// PackageHandler implements the Step 7 package inventory/update API.
// Every GET individually checks vm.view (spec §50); scan/refresh/
// acknowledge/dismiss are admin-only (spec §29/§51), enforced in
// router.go via requireAdmin, not re-checked here -- consistent with how
// vm_ssh.go's write endpoints work.
type PackageHandler struct {
	store           *repository.Store
	authz           *services.AuthorizationService
	packages        *services.PackageService
	scheduler       *services.PackageScanScheduler
	externalScanner *services.ExternalPackageScanner
	audit           *services.AuditService
}

// NewPackageHandler creates a PackageHandler.
func NewPackageHandler(store *repository.Store, authz *services.AuthorizationService, packages *services.PackageService, scheduler *services.PackageScanScheduler, externalScanner *services.ExternalPackageScanner, audit *services.AuditService) *PackageHandler {
	return &PackageHandler{store: store, authz: authz, packages: packages, scheduler: scheduler, externalScanner: externalScanner, audit: audit}
}

// authorizeVMView resolves :id and checks vm.view, returning the VM's
// resource ID and internal vms.id row ID. 404-not-403 on failure, same as
// every other VM-scoped endpoint since Step 3.
func (h *PackageHandler) authorizeVMView(w http.ResponseWriter, r *http.Request) (resourceID, vmRowID uuid.UUID, ok bool) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return uuid.Nil, uuid.Nil, false
	}
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return uuid.Nil, uuid.Nil, false
	}
	allowed, err := h.authz.CanAccessVMAny(r.Context(), user, resourceID, services.PermVMView, services.PermVMUpdates)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return uuid.Nil, uuid.Nil, false
	}
	if !allowed {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return uuid.Nil, uuid.Nil, false
	}
	vm, err := h.store.GetVMByResourceID(r.Context(), resourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return uuid.Nil, uuid.Nil, false
	}
	return resourceID, vm.ID, true
}

func pagination(r *http.Request) (limit, offset int32, page, pageSize int) {
	pageSize = defaultPackagePageSize
	if v := r.URL.Query().Get("page_size"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			pageSize = parsed
		}
	}
	if pageSize > maxPackagePageSize {
		pageSize = maxPackagePageSize
	}
	page = 1
	if v := r.URL.Query().Get("page"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			page = parsed
		}
	}
	return int32(pageSize), int32((page - 1) * pageSize), page, pageSize
}

func optionalText(v string) pgtype.Text {
	if v == "" {
		return pgtype.Text{}
	}
	return pgutil.Text(v)
}

func optionalBool(v string) pgtype.Bool {
	if v == "" {
		return pgtype.Bool{}
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return pgtype.Bool{}
	}
	return pgutil.Bool(b)
}

// --- DTOs ---

type packageDTO struct {
	ID               string  `json:"id"`
	Name             string  `json:"name"`
	InstalledVersion string  `json:"installed_version"`
	AvailableVersion *string `json:"available_version,omitempty"`
	Architecture     string  `json:"architecture"`
	PackageManager   string  `json:"package_manager"`
	Description      string  `json:"description,omitempty"`
	Status           string  `json:"status"` // UP_TO_DATE | UPDATE_AVAILABLE | SECURITY_UPDATE
	Severity         *string `json:"severity,omitempty"`
	IsSecurityUpdate bool    `json:"is_security_update"`
	LastDiscoveredAt *string `json:"last_discovered_at,omitempty"`
	// CreatedAt is when this package row was first seen by our own
	// scanner -- primarily useful when listing with
	// ?new_since_baseline=true (the "Installed Since Onboarding" view),
	// as a fallback for InstalledAt below.
	CreatedAt string `json:"created_at"`
	// InstalledAt is the package manager's own install-time record (APT
	// dpkg-info mtime, RPM INSTALLTIME) when available -- more accurate
	// than CreatedAt for "when was this actually installed on the VM",
	// since a delayed first scan can discover a package long after it was
	// really installed. Nil for ecosystems that don't expose one
	// (pip/npm/gem/snap); the "new since baseline" filter itself already
	// falls back to CreatedAt server-side when this is nil.
	InstalledAt *string `json:"installed_at,omitempty"`
}

func toPackageDTO(row generated.ListPackagesWithStatusRow) packageDTO {
	dto := packageDTO{
		ID: row.ID.String(), Name: row.Name, InstalledVersion: row.InstalledVersion,
		Architecture: row.Architecture, PackageManager: row.PackageManager,
		Description: pgutil.TextOrEmpty(row.Description), LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt),
		CreatedAt:   row.CreatedAt.Time.Format(time.RFC3339),
		InstalledAt: formatTimestamptz(row.InstalledAt),
	}
	if row.UpdateID.Valid {
		dto.AvailableVersion = pgutil.StringPtr(row.AvailableVersion)
		dto.IsSecurityUpdate = row.IsSecurityUpdate.Bool
		if row.SecurityStatus.String == string(services.SecurityConfirmed) {
			dto.Status = "SECURITY_UPDATE"
		} else {
			dto.Status = "UPDATE_AVAILABLE"
		}
		dto.Severity = pgutil.StringPtr(row.UpdateSeverity)
	} else {
		dto.Status = "UP_TO_DATE"
	}
	return dto
}

// List handles GET /api/vms/:id/packages?search=&status=&security=&package_manager=&page=&page_size=.
func (h *PackageHandler) List(w http.ResponseWriter, r *http.Request) {
	resourceID, vmRowID, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	_ = resourceID
	limit, offset, page, pageSize := pagination(r)
	q := r.URL.Query()
	params := generated.ListPackagesWithStatusParams{
		VmID: vmRowID, Limit: limit, Offset: offset,
		Search: optionalText(q.Get("search")), PackageManager: optionalText(q.Get("package_manager")),
		SecurityOnly: optionalBool(q.Get("security")), Status: optionalText(q.Get("status")),
		NewSinceBaseline: optionalBool(q.Get("new_since_baseline")),
	}
	rows, err := h.store.ListPackagesWithStatus(r.Context(), params)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load packages")
		return
	}
	total, err := h.store.CountPackagesWithStatus(r.Context(), generated.CountPackagesWithStatusParams{
		VmID: vmRowID, Search: params.Search, PackageManager: params.PackageManager, SecurityOnly: params.SecurityOnly, Status: params.Status,
		NewSinceBaseline: params.NewSinceBaseline,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to count packages")
		return
	}

	items := make([]packageDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, toPackageDTO(row))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"packages": items, "page": page, "page_size": pageSize, "total": total,
	})
}

// Get handles GET /api/vms/:id/packages/:packageId.
func (h *PackageHandler) Get(w http.ResponseWriter, r *http.Request) {
	_, vmRowID, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	packageID, err := uuid.Parse(r.PathValue("packageId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "package not found")
		return
	}
	row, err := h.store.GetPackageWithStatusByID(r.Context(), generated.GetPackageWithStatusByIDParams{ID: packageID, VmID: vmRowID})
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "package not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toPackageDTO(generated.ListPackagesWithStatusRow(row)))
}

type packageUpdateDTO struct {
	ID                   string `json:"id"`
	PackageID            string `json:"package_id"`
	PackageName          string `json:"package_name"`
	CurrentVersion       string `json:"current_version"`
	AvailableVersion     string `json:"available_version"`
	Architecture         string `json:"architecture,omitempty"`
	Release              string `json:"release,omitempty"`
	Severity             string `json:"severity"`
	IsSecurityUpdate     bool   `json:"is_security_update"`
	SecurityStatus       string `json:"security_status"`
	RecommendationStatus string `json:"recommendation_status"`
	DetectedAt           string `json:"detected_at"`
}

// ListUpdates handles GET /api/vms/:id/packages/updates?search=&security=&page=&page_size=.
func (h *PackageHandler) ListUpdates(w http.ResponseWriter, r *http.Request) {
	_, vmRowID, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	limit, offset, page, pageSize := pagination(r)
	q := r.URL.Query()
	params := generated.ListPackageUpdatesByVMParams{
		VmID: vmRowID, Limit: limit, Offset: offset,
		Search: optionalText(q.Get("search")), SecurityOnly: optionalBool(q.Get("security")),
	}
	rows, err := h.store.ListPackageUpdatesByVM(r.Context(), params)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load package updates")
		return
	}
	total, err := h.store.CountPackageUpdatesByVM(r.Context(), generated.CountPackageUpdatesByVMParams{
		VmID: vmRowID, Search: params.Search, SecurityOnly: params.SecurityOnly,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to count package updates")
		return
	}

	items := make([]packageUpdateDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, packageUpdateDTO{
			ID: row.ID.String(), PackageID: row.PackageID.String(), PackageName: row.PackageName,
			CurrentVersion: row.CurrentVersion, AvailableVersion: row.AvailableVersion,
			Architecture: pgutil.TextOrEmpty(row.Architecture), Release: pgutil.TextOrEmpty(row.Release),
			Severity: row.Severity, IsSecurityUpdate: row.IsSecurityUpdate, SecurityStatus: row.SecurityStatus,
			RecommendationStatus: row.RecommendationStatus, DetectedAt: row.DetectedAt.Time.Format(time.RFC3339),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"updates": items, "page": page, "page_size": pageSize, "total": total,
	})
}

// Summary handles GET /api/vms/:id/packages/summary.
func (h *PackageHandler) Summary(w http.ResponseWriter, r *http.Request) {
	_, vmRowID, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	summary, err := h.store.GetPackageSummaryByVM(r.Context(), vmRowID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load package summary")
		return
	}
	resp := map[string]any{
		"total": summary.Total, "up_to_date": summary.UpToDate,
		"updates_available": summary.UpdatesAvailable, "security_updates": summary.SecurityUpdates,
	}
	if run, err := h.store.GetLatestPackageDiscoveryRun(r.Context(), vmRowID); err == nil {
		if t := pgutil.TimePtr(run.CompletedAt); t != nil {
			formatted := t.Format(time.RFC3339)
			resp["last_scan"] = formatted
		}
	}
	if vm, err := h.store.GetVMByID(r.Context(), vmRowID); err == nil {
		if t := pgutil.TimePtr(vm.PackageBaselineAt); t != nil {
			formatted := t.Format(time.RFC3339)
			resp["package_baseline_at"] = formatted
		}
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// ResetBaseline handles PUT /api/vms/:id/packages/baseline (admin-only):
// "Reset Baseline to Now" for a VM that was already customized before
// onboarding, so "Installed Since Onboarding" starts counting from this
// moment instead of the VM's first scan.
func (h *PackageHandler) ResetBaseline(w http.ResponseWriter, r *http.Request) {
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
	updated, err := h.store.SetVMPackageBaselineNow(r.Context(), vm.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to reset package baseline")
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditPackageBaselineReset, ResourceType: "VM", ResourceID: &resourceID,
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]string{
		"package_baseline_at": updated.PackageBaselineAt.Time.Format(time.RFC3339),
	})
}

type discoveryRunDTO struct {
	ID             string  `json:"id"`
	PackageManager string  `json:"package_manager,omitempty"`
	Status         string  `json:"status"`
	PackageCount   *int32  `json:"package_count,omitempty"`
	StartedAt      string  `json:"started_at"`
	CompletedAt    *string `json:"completed_at,omitempty"`
	ErrorSummary   *string `json:"error_summary,omitempty"`
}

// DiscoveryStatus handles GET /api/vms/:id/packages/discovery-status.
func (h *PackageHandler) DiscoveryStatus(w http.ResponseWriter, r *http.Request) {
	_, vmRowID, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	runs, err := h.store.ListPackageDiscoveryRunsByVM(r.Context(), generated.ListPackageDiscoveryRunsByVMParams{VmID: vmRowID, Limit: 10})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load discovery history")
		return
	}
	items := make([]discoveryRunDTO, 0, len(runs))
	for _, run := range runs {
		item := discoveryRunDTO{
			ID: run.ID.String(), PackageManager: pgutil.TextOrEmpty(run.PackageManager),
			Status: run.Status, PackageCount: pgutil.Int4Ptr(run.PackageCount),
			StartedAt: run.StartedAt.Time.Format(time.RFC3339),
		}
		if t := pgutil.TimePtr(run.CompletedAt); t != nil {
			formatted := t.Format(time.RFC3339)
			item.CompletedAt = &formatted
		}
		item.ErrorSummary = pgutil.StringPtr(run.ErrorSummary)
		items = append(items, item)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"runs": items})
}

type scanResultDTO struct {
	Status         string `json:"status"`
	PackageManager string `json:"package_manager,omitempty"`
	PackageCount   int    `json:"package_count"`
	UpdateCount    int    `json:"update_count"`
	ErrorSummary   string `json:"error_summary,omitempty"`
}

// Scan handles POST /api/vms/:id/packages/scan (admin-only, spec §9/§29).
func (h *PackageHandler) Scan(w http.ResponseWriter, r *http.Request) {
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
		UserID: &actor.ID, Action: services.AuditPackageScanStarted, ResourceType: "VM", ResourceID: &resourceID,
	})

	result, err := h.scheduler.ScanNow(r.Context(), resourceID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrPackageScanInProgress), errors.Is(err, services.ErrPackageScanRateLimited):
			httpx.WriteError(w, http.StatusTooManyRequests, err.Error())
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "scan failed")
		}
		return
	}

	action := services.AuditPackageScanCompleted
	if result.Status == "FAILED" {
		action = services.AuditPackageScanFailed
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: action, ResourceType: "VM", ResourceID: &resourceID,
		Metadata: map[string]any{"status": result.Status, "package_count": result.PackageCount, "update_count": result.UpdateCount},
	})

	httpx.WriteJSON(w, http.StatusOK, scanResultDTO{
		Status: result.Status, PackageManager: string(result.PackageManager),
		PackageCount: result.PackageCount, UpdateCount: result.UpdateCount, ErrorSummary: result.ErrorSummary,
	})
}

// Refresh handles POST /api/vms/:id/packages/refresh (admin-only).
func (h *PackageHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	if _, err := h.store.GetVMResourceByID(r.Context(), resourceID); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}

	result, err := h.scheduler.RefreshNow(r.Context(), resourceID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrPackageScanInProgress), errors.Is(err, services.ErrPackageScanRateLimited):
			httpx.WriteError(w, http.StatusTooManyRequests, err.Error())
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "refresh failed")
		}
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditPackageMetadataRefreshed, ResourceType: "VM", ResourceID: &resourceID,
		Metadata: map[string]any{"status": result.Status, "update_count": result.UpdateCount},
	})

	httpx.WriteJSON(w, http.StatusOK, scanResultDTO{
		Status: result.Status, PackageManager: string(result.PackageManager),
		PackageCount: result.PackageCount, UpdateCount: result.UpdateCount, ErrorSummary: result.ErrorSummary,
	})
}

func (h *PackageHandler) setUpdateStatus(w http.ResponseWriter, r *http.Request, status, auditAction string) {
	resourceID, vmRowID, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	packageID, err := uuid.Parse(r.PathValue("packageId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "package not found")
		return
	}
	// packageId here identifies the packages row; resolve its active
	// update (if any) to acknowledge/dismiss.
	pkgRow, err := h.store.GetPackageWithStatusByID(r.Context(), generated.GetPackageWithStatusByIDParams{ID: packageID, VmID: vmRowID})
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "package not found")
		return
	}
	if !pkgRow.UpdateID.Valid {
		httpx.WriteError(w, http.StatusBadRequest, "this package has no active update to acknowledge or dismiss")
		return
	}
	updateID := pgutil.UUID(pkgRow.UpdateID)
	if _, err := h.store.SetPackageUpdateStatus(r.Context(), generated.SetPackageUpdateStatusParams{
		ID: updateID, VmID: vmRowID, RecommendationStatus: status,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.WriteError(w, http.StatusNotFound, "package update not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to update package status")
		return
	}
	// Keep the linked recommendation's status in sync (spec §20: acknowledging
	// or dismissing an update should read the same way on the
	// /recommendations dashboard as it does here) -- SetRecommendationStatusBySource
	// sets exactly the requested status (ACKNOWLEDGED/DISMISSED), never
	// RESOLVED, which is reserved for the automatic scan-sync path in
	// PackageService.checkAndSyncUpdates.
	if err := h.store.SetRecommendationStatusBySource(r.Context(), generated.SetRecommendationStatusBySourceParams{
		SourceType: pgutil.Text("package_update"), SourceID: pgutil.NullUUID(&updateID), Status: status,
	}); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to update recommendation")
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: auditAction, ResourceType: "VM", ResourceID: &resourceID,
		Metadata: map[string]any{"package": pkgRow.Name},
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Acknowledge handles POST /api/vms/:id/packages/:packageId/acknowledge (admin-only).
func (h *PackageHandler) Acknowledge(w http.ResponseWriter, r *http.Request) {
	h.setUpdateStatus(w, r, "ACKNOWLEDGED", services.AuditPackageRecommendationAcknowledged)
}

// Dismiss handles POST /api/vms/:id/packages/:packageId/dismiss (admin-only).
func (h *PackageHandler) Dismiss(w http.ResponseWriter, r *http.Request) {
	h.setUpdateStatus(w, r, "DISMISSED", services.AuditPackageRecommendationDismissed)
}

// --- Externally installed packages (pip/npm/gem/snap): list-only, no
// update checking -- see ExternalPackageScanner's own doc comment for why. ---

type externalPackageDTO struct {
	ID               string  `json:"id"`
	Name             string  `json:"name"`
	InstalledVersion string  `json:"installed_version"`
	PackageManager   string  `json:"package_manager"`
	LastDiscoveredAt *string `json:"last_discovered_at,omitempty"`
}

func toExternalPackageDTO(row generated.Package) externalPackageDTO {
	return externalPackageDTO{
		ID: row.ID.String(), Name: row.Name, InstalledVersion: row.InstalledVersion,
		PackageManager: row.PackageManager, LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt),
	}
}

// ListExternal handles GET /api/vms/:id/external-packages.
func (h *PackageHandler) ListExternal(w http.ResponseWriter, r *http.Request) {
	_, vmRowID, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	rows, err := h.store.ListExternalPackagesForVM(r.Context(), vmRowID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load external packages")
		return
	}
	dtos := make([]externalPackageDTO, 0, len(rows))
	for _, row := range rows {
		dtos = append(dtos, toExternalPackageDTO(row))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"packages": dtos})
}

type externalScanResultDTO struct {
	Status       string `json:"status"`
	PackageCount int    `json:"package_count"`
	ErrorSummary string `json:"error_summary,omitempty"`
}

// ScanExternal handles POST /api/vms/:id/external-packages/scan (admin-only).
func (h *PackageHandler) ScanExternal(w http.ResponseWriter, r *http.Request) {
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
		UserID: &actor.ID, Action: services.AuditExternalPackageScanStarted, ResourceType: "VM", ResourceID: &resourceID,
	})

	result, err := h.externalScanner.Scan(r.Context(), resourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scan failed")
		return
	}

	action := services.AuditExternalPackageScanCompleted
	if result.Status == "FAILED" {
		action = services.AuditExternalPackageScanFailed
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: action, ResourceType: "VM", ResourceID: &resourceID,
		Metadata: map[string]any{"status": result.Status, "package_count": result.PackageCount},
	})

	httpx.WriteJSON(w, http.StatusOK, externalScanResultDTO{
		Status: result.Status, PackageCount: result.PackageCount, ErrorSummary: result.ErrorSummary,
	})
}
