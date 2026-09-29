package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// ObjectStorageHandler implements the standalone object storage
// CRUD/monitoring API (Step 17): an object storage bucket is a
// first-class resource under a Project (optionally a Group) -- never a VM
// child. Every object-storage-scoped endpoint verifies the requested
// object storage actually exists and that the caller holds the required
// permission on its owning resource, 404-not-403 on any failure --
// mirrors DatabaseHandler exactly. No write/delete/upload S3 API surface
// exists anywhere in this phase.
type ObjectStorageHandler struct {
	store             *repository.Store
	authz             *services.AuthorizationService
	access            *services.AccessService
	service           *services.ObjectStorageService
	credentials       *services.StandaloneObjectStorageCredentialService
	cache             *services.ObjectStorageMetricsCache
	audit             *services.AuditService
	connectionTimeout time.Duration
	commandTimeout    time.Duration
}

// NewObjectStorageHandler creates an ObjectStorageHandler.
func NewObjectStorageHandler(
	store *repository.Store, authz *services.AuthorizationService, access *services.AccessService, service *services.ObjectStorageService,
	credentials *services.StandaloneObjectStorageCredentialService, cache *services.ObjectStorageMetricsCache, audit *services.AuditService,
	connectionTimeout, commandTimeout time.Duration,
) *ObjectStorageHandler {
	return &ObjectStorageHandler{
		store: store, authz: authz, access: access, service: service, credentials: credentials, cache: cache, audit: audit,
		connectionTimeout: connectionTimeout, commandTimeout: commandTimeout,
	}
}

// authorizeObjectStorage resolves :id and verifies the caller holds
// requiredPermission on the object storage's owning resource --
// 404-not-403 on any failure, mirroring DatabaseHandler.authorizeDatabase
// exactly so existence is never disclosed to an unauthorized caller.
func (h *ObjectStorageHandler) authorizeObjectStorage(w http.ResponseWriter, r *http.Request, requiredPermission string) (generated.ObjectStorage, bool) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return generated.ObjectStorage{}, false
	}
	objectStorageID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "object storage not found")
		return generated.ObjectStorage{}, false
	}
	os, err := h.store.GetObjectStorageByID(r.Context(), objectStorageID)
	if err != nil || os.DeletedAt.Valid {
		httpx.WriteError(w, http.StatusNotFound, "object storage not found")
		return generated.ObjectStorage{}, false
	}
	allowed, err := h.authz.CanAccessObjectStorage(r.Context(), user, os.ResourceID, requiredPermission)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return generated.ObjectStorage{}, false
	}
	if !allowed {
		httpx.WriteError(w, http.StatusNotFound, "object storage not found")
		return generated.ObjectStorage{}, false
	}
	return os, true
}

// --- DTOs ---

type objectStorageDTO struct {
	ID                   string                              `json:"id"`
	ResourceID           string                              `json:"resource_id"`
	Name                 string                              `json:"name,omitempty"`
	WorkspaceName        string                              `json:"workspace_name,omitempty"`
	Provider             string                              `json:"provider"`
	Endpoint             string                              `json:"endpoint,omitempty"`
	Region               string                              `json:"region,omitempty"`
	Bucket               string                              `json:"bucket"`
	BasePath             string                              `json:"base_path,omitempty"`
	AccessKeyID          string                              `json:"access_key_id,omitempty"`
	MonitoringEnabled    bool                                `json:"monitoring_enabled"`
	ConnectionStatus     string                              `json:"connection_status"`
	TLSEnabled           bool                                `json:"tls_enabled"`
	TLSSkipVerify        bool                                `json:"tls_skip_verify"`
	LastMetricsAt        *string                             `json:"last_metrics_at,omitempty"`
	HealthStatus         string                              `json:"health_status"`
	VersioningStatus     string                              `json:"versioning_status"`
	EncryptionStatus     string                              `json:"encryption_status"`
	PublicAccess         string                              `json:"public_access"`
	ObjectLockStatus     string                              `json:"object_lock_status"`
	CredentialConfigured bool                                `json:"credential_configured"`
	Permissions          []string                            `json:"permissions,omitempty"`
	Capabilities         *services.ObjectStorageCapabilities `json:"capabilities,omitempty"`
	// Fast-metrics enrichment (Step 17 Phase 2), from the latest
	// cached/DB object_storage_metrics row -- absent (never 0) until this
	// storage has actually been monitored at least once.
	ObjectCount    *int64  `json:"object_count,omitempty"`
	TotalSizeBytes *int64  `json:"total_size_bytes,omitempty"`
	LastCheckedAt  *string `json:"last_checked_at,omitempty"`
	// Deep-metrics enrichment (Step 17 Phase 3): embedded directly on the
	// detail response so the frontend never needs 3 extra round trips to
	// GET .../security, .../growth, .../health -- each stays absent
	// (never a fabricated value) until at least one deep cycle has run.
	Security         *objectStorageSecurityDTO `json:"security,omitempty"`
	GrowthProjection *objectStorageGrowthDTO   `json:"growth_projection,omitempty"`
	HealthReasons    []string                  `json:"health_reasons,omitempty"`
}

// toObjectStorageDTO never includes a secret access key anywhere (spec:
// GET/list responses must never include secret_access_key or the
// credential's decrypted value) -- only access_key_id (plaintext, not a
// secret) and credential_configured, a boolean.
func (h *ObjectStorageHandler) toObjectStorageDTO(r *http.Request, os generated.ObjectStorage) objectStorageDTO {
	dto := objectStorageDTO{
		ID: os.ID.String(), ResourceID: os.ResourceID.String(), Provider: os.Provider,
		Endpoint: pgutil.TextOrEmpty(os.Endpoint), Region: pgutil.TextOrEmpty(os.Region), Bucket: os.Bucket,
		BasePath: pgutil.TextOrEmpty(os.BasePath), AccessKeyID: pgutil.TextOrEmpty(os.AccessKeyID),
		MonitoringEnabled: os.MonitoringEnabled, ConnectionStatus: os.ConnectionStatus,
		TLSEnabled: os.TlsEnabled, TLSSkipVerify: os.TlsSkipVerify, LastMetricsAt: formatTimestamptz(os.LastMetricsAt),
		HealthStatus: os.HealthStatus, VersioningStatus: os.VersioningStatus, EncryptionStatus: os.EncryptionStatus,
		PublicAccess: os.PublicAccess, ObjectLockStatus: os.ObjectLockStatus, Name: pgutil.TextOrEmpty(os.Name),
	}
	if configured, err := h.credentials.HasSecretKey(r.Context(), os.ID); err == nil {
		dto.CredentialConfigured = configured
	}
	dto.ObjectCount, dto.TotalSizeBytes, dto.LastCheckedAt = h.latestMetricSummary(r, os.ID)
	return dto
}

// latestMetricSummary returns the object_count/total_size_bytes/
// last_checked_at enrichment toObjectStorageDTO and List use: the cache's
// latest sample if present (Step 17 Phase 2's single-collector-many-
// viewers cache, never triggers a new connection on read), else the
// latest object_storage_metrics DB row, else all three nil -- a storage
// that was never monitored must never surface a fabricated 0 here.
func (h *ObjectStorageHandler) latestMetricSummary(r *http.Request, objectStorageID uuid.UUID) (objectCount, totalSizeBytes *int64, lastCheckedAt *string) {
	if entry, found := h.cache.Get(objectStorageID); found {
		captured := entry.CapturedAt.Format(time.RFC3339)
		return entry.Snapshot.ObjectCount, entry.Snapshot.TotalSizeBytes, &captured
	}
	row, err := h.store.GetLatestObjectStorageMetric(r.Context(), objectStorageID)
	if err != nil {
		return nil, nil, nil
	}
	objectCount = pgutil.Int8Ptr(row.ObjectCount)
	totalSizeBytes = pgutil.Int8Ptr(row.TotalSizeBytes)
	if row.CapturedAt.Valid {
		captured := row.CapturedAt.Time.Format(time.RFC3339)
		lastCheckedAt = &captured
	}
	return objectCount, totalSizeBytes, lastCheckedAt
}

// enrichedObjectStorageDTO adds the resource's display name and owning
// workspace's name (not carried on the bare `object_storages` row) --
// best effort, mirrors DatabaseHandler.enrichedDatabaseDTO exactly.
func (h *ObjectStorageHandler) enrichedObjectStorageDTO(r *http.Request, os generated.ObjectStorage) objectStorageDTO {
	dto := h.toObjectStorageDTO(r, os)
	if detail, err := h.store.GetObjectStorageWithResourceByID(r.Context(), os.ID); err == nil {
		dto.Name = detail.ResourceName
		dto.WorkspaceName = detail.WorkspaceName
	}
	return dto
}

// permissionsForObjectStorage computes the caller-scoped permissions
// array the frontend's tab-hiding logic depends on (decision: mirror the
// VM `permissions: string[]` pattern) -- an Admin gets all four grantable
// permissions implicitly (Admin never needs an explicit grant), a Member
// gets whatever EffectiveObjectStorageAccess resolves.
func (h *ObjectStorageHandler) permissionsForObjectStorage(r *http.Request, user services.AuthenticatedUser, resourceID uuid.UUID) []string {
	if user.IsAdmin() {
		return []string{
			services.PermObjectStorageView, services.PermObjectStorageMonitor,
			services.PermObjectStorageBrowser, services.PermObjectStorageDownload,
		}
	}
	access, err := h.authz.EffectiveObjectStorageAccess(r.Context(), user.ID, resourceID)
	if err != nil || access == nil {
		return []string{}
	}
	return access.Permissions
}

// List handles GET /api/object-storage -- scoped to the caller's
// authorized object storages, mirrors DatabaseHandler.List exactly.
func (h *ObjectStorageHandler) List(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var resourceIDs []uuid.UUID
	if !user.IsAdmin() {
		access, err := h.authz.GetUserObjectStorageAccess(r.Context(), user)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
			return
		}
		resourceIDs = make([]uuid.UUID, 0, len(access))
		for _, a := range access {
			resourceIDs = append(resourceIDs, a.ResourceID)
		}
	}
	rows, err := h.store.ListObjectStoragesForDashboard(r.Context(), resourceIDs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load object storages")
		return
	}
	items := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		item := map[string]any{
			"id": row.ID.String(), "resource_id": row.ResourceID.String(), "name": pgutil.TextOrEmpty(row.ResourceName),
			"workspace_id": pgutil.UUIDPtr(row.WorkspaceID), "workspace_name": pgutil.TextOrEmpty(row.WorkspaceName),
			"provider": row.Provider, "endpoint": pgutil.TextOrEmpty(row.Endpoint),
			"region": pgutil.TextOrEmpty(row.Region), "bucket": row.Bucket, "base_path": pgutil.TextOrEmpty(row.BasePath),
			"monitoring_enabled": row.MonitoringEnabled, "connection_status": row.ConnectionStatus, "health_status": row.HealthStatus,
			"permissions": h.permissionsForObjectStorage(r, user, row.ResourceID),
		}
		// Fast-metrics enrichment (Step 17 Phase 2): populates the list
		// page's Objects/Size columns once this storage has been monitored
		// at least once -- keys are omitted entirely (never present as
		// null/0) when nothing has been collected yet.
		objectCount, totalSizeBytes, lastCheckedAt := h.latestMetricSummary(r, row.ID)
		if objectCount != nil {
			item["object_count"] = *objectCount
		}
		if totalSizeBytes != nil {
			item["total_size_bytes"] = *totalSizeBytes
		}
		if lastCheckedAt != nil {
			item["last_checked_at"] = *lastCheckedAt
		}
		items = append(items, item)
	}
	// Key is "storages", not "object_storages" -- matches
	// frontend/src/lib/api.ts's listObjectStorage() contract exactly
	// (`{ storages: ObjectStorageListItem[]; total: number }`), verified
	// directly against the shipped frontend source during Step 17's final
	// integration pass. This was a pre-existing key-name mismatch (found,
	// not introduced, by this pass) that would have made the Object Storage
	// list page always render empty.
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"storages": items, "total": len(items)})
}

// Summary handles GET /api/object-storage/summary: total plus a
// healthy/warning/critical/unavailable partition (see
// sql/queries/storage.sql's GetObjectStorageSummaryCounts for the exact,
// documented unavailable-vs-critical split rule) over the caller's
// authorized object storages -- scoped exactly like List (nil resource_ids
// for an Admin, the caller's GetUserObjectStorageAccess resource IDs
// otherwise), never a global count for a Member. Requires
// object_storage.view (enforced at the router via requireAuth; this
// endpoint itself needs no :id so there is nothing for
// authorizeObjectStorage to resolve).
func (h *ObjectStorageHandler) Summary(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var resourceIDs []uuid.UUID
	if !user.IsAdmin() {
		access, err := h.authz.GetUserObjectStorageAccess(r.Context(), user)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
			return
		}
		resourceIDs = make([]uuid.UUID, 0, len(access))
		for _, a := range access {
			resourceIDs = append(resourceIDs, a.ResourceID)
		}
	}
	counts, err := h.store.GetObjectStorageSummaryCounts(r.Context(), resourceIDs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load object storage summary")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"total": counts.Total, "healthy": counts.Healthy, "warning": counts.Warning,
		"critical": counts.Critical, "unavailable": counts.Unavailable,
	})
}

// Get handles GET /api/object-storage/:id. Response includes both a
// caller-scoped `permissions` array (the frontend's tab-hiding logic
// depends on this field being present and accurate) and the provider's
// `capabilities` map.
func (h *ObjectStorageHandler) Get(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageView)
	if !ok {
		return
	}
	user, _ := services.UserFromContext(r.Context())
	dto := h.enrichedObjectStorageDTO(r, os)
	dto.Permissions = h.permissionsForObjectStorage(r, user, os.ResourceID)
	capabilities := services.CapabilitiesForProvider(os.Provider)
	dto.Capabilities = &capabilities
	security := h.securityDTO(os)
	dto.Security = &security
	// Embedded on the detail response, growth_projection is an all-or-
	// nothing signal the frontend uses to decide whether to render the
	// projection card at all -- a partial {current_bytes} object (which
	// growthDTO does return from the dedicated GET .../growth endpoint,
	// where partial/absent fields are the normal per-field contract) would
	// be truthy and get rendered with "N/A"-style holes for the still-
	// missing growth rate/estimate, which is exactly the fabricated-looking
	// half-answer this feature is designed to avoid. Only embed once the
	// full projection (current + growth rate + estimate) is available.
	if growth := h.growthDTO(r.Context(), os); growth != nil && growth.GrowthBytesPerDay != nil {
		dto.GrowthProjection = growth
	}
	_, dto.HealthReasons = h.computeObjectStorageHealth(r.Context(), os)
	httpx.WriteJSON(w, http.StatusOK, dto)
}

type configureObjectStorageRequest struct {
	WorkspaceID     string `json:"workspace_id"`
	Name            string `json:"name"`
	Provider        string `json:"provider"`
	Endpoint        string `json:"endpoint,omitempty"`
	Region          string `json:"region,omitempty"`
	Bucket          string `json:"bucket"`
	BasePath        string `json:"base_path,omitempty"`
	TLSEnabled      bool   `json:"tls_enabled"`
	TLSSkipVerify   bool   `json:"tls_skip_verify"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
}

// Configure handles POST /api/object-storage (admin-only): manual
// registration of a standalone object storage bucket for monitoring.
// Never accepts a write/delete/upload field of any kind.
func (h *ObjectStorageHandler) Configure(w http.ResponseWriter, r *http.Request) {
	var req configureObjectStorageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	workspaceID, err := uuid.Parse(req.WorkspaceID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid workspace_id")
		return
	}

	os, err := h.service.Configure(r.Context(), services.ConfigureObjectStorageInput{
		WorkspaceID: workspaceID, Name: req.Name, Provider: req.Provider, Endpoint: req.Endpoint,
		Region: req.Region, Bucket: req.Bucket, BasePath: req.BasePath, TLSEnabled: req.TLSEnabled, TLSSkipVerify: req.TLSSkipVerify,
		AccessKeyID: req.AccessKeyID, SecretAccessKey: req.SecretAccessKey,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditObjectStorageCreated, ResourceType: "OBJECT_STORAGE", ResourceID: &os.ResourceID,
		Metadata: map[string]any{"provider": os.Provider},
	})
	httpx.WriteJSON(w, http.StatusCreated, h.enrichedObjectStorageDTO(r, os))
}

type updateObjectStorageRequest struct {
	Name              *string `json:"name,omitempty"`
	Provider          *string `json:"provider,omitempty"`
	Endpoint          *string `json:"endpoint,omitempty"`
	Region            *string `json:"region,omitempty"`
	Bucket            *string `json:"bucket,omitempty"`
	BasePath          *string `json:"base_path,omitempty"`
	TLSEnabled        *bool   `json:"tls_enabled,omitempty"`
	TLSSkipVerify     *bool   `json:"tls_skip_verify,omitempty"`
	AccessKeyID       *string `json:"access_key_id,omitempty"`
	SecretAccessKey   *string `json:"secret_access_key,omitempty"`
	MonitoringEnabled *bool   `json:"monitoring_enabled,omitempty"`
}

// Update handles PATCH /api/object-storage/:id (admin-only).
func (h *ObjectStorageHandler) Update(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageView)
	if !ok {
		return
	}
	var req updateObjectStorageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	updated, err := h.service.Update(r.Context(), os.ID, services.UpdateObjectStorageInput{
		Name: req.Name, Provider: req.Provider, Endpoint: req.Endpoint, Region: req.Region, Bucket: req.Bucket,
		BasePath: req.BasePath, TLSEnabled: req.TLSEnabled, TLSSkipVerify: req.TLSSkipVerify,
		AccessKeyID: req.AccessKeyID, SecretAccessKey: req.SecretAccessKey,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.MonitoringEnabled != nil {
		updated, err = h.service.SetMonitoringEnabled(r.Context(), os.ID, *req.MonitoringEnabled)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to update monitoring state")
			return
		}
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{UserID: &actor.ID, Action: services.AuditObjectStorageUpdated, ResourceType: "OBJECT_STORAGE", ResourceID: &updated.ResourceID})
	httpx.WriteJSON(w, http.StatusOK, h.enrichedObjectStorageDTO(r, updated))
}

// Delete handles DELETE /api/object-storage/:id (admin-only):
// soft-deletes the monitoring registration only -- never touches the
// real S3 bucket or any object inside it.
// Delete handles DELETE /api/object-storage/:id. Step 22: now requires the
// resource's exact current name as confirmation_name, validated
// server-side against the canonical resources.name -- previously this
// deleted immediately with no confirmation check at all. Never deletes,
// modifies, or touches the actual bucket/objects -- only this
// application's own monitoring registration.
func (h *ObjectStorageHandler) Delete(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageView)
	if !ok {
		return
	}
	var req deleteConfirmationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	resource, err := h.store.GetResourceByID(r.Context(), os.ResourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "object storage not found")
		return
	}
	if req.ConfirmationName != resource.Name {
		httpx.WriteError(w, http.StatusBadRequest, services.ErrConfirmationMismatch.Error())
		return
	}
	if err := h.service.Delete(r.Context(), os.ID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to delete object storage")
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditObjectStorageDeleted, ResourceType: "OBJECT_STORAGE", ResourceID: &os.ResourceID,
		Metadata: map[string]any{"name": resource.Name},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// TestConnection handles POST /api/object-storage/:id/test-connection
// (admin-only): runs exactly one backend-defined, read-only HeadBucket
// probe -- never accepts a client-supplied operation of any kind.
func (h *ObjectStorageHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageView)
	if !ok {
		return
	}
	secretAccessKey, _ := h.credentials.GetSecretKey(r.Context(), os.ID)
	conn := services.ObjectStorageConnection{
		Provider: os.Provider, Endpoint: pgutil.TextOrEmpty(os.Endpoint), Region: pgutil.TextOrEmpty(os.Region), Bucket: os.Bucket,
		BasePath: pgutil.TextOrEmpty(os.BasePath), AccessKeyID: pgutil.TextOrEmpty(os.AccessKeyID), SecretAccessKey: secretAccessKey,
		TLSEnabled: os.TlsEnabled, TLSSkipVerify: os.TlsSkipVerify, ConnectTimeout: h.connectionTimeout, CommandTimeout: h.commandTimeout,
	}
	status, _ := services.TestObjectStorageConnection(r.Context(), conn)
	health := services.ComputeObjectStorageHealth(status)
	_, _ = h.store.UpdateObjectStorageConnectionStatus(r.Context(), generated.UpdateObjectStorageConnectionStatusParams{
		ID: os.ID, ConnectionStatus: string(status), HealthStatus: string(health),
	})

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditObjectStorageConnectionTested, ResourceType: "OBJECT_STORAGE", ResourceID: &os.ResourceID,
		Metadata: map[string]any{"connection_status": string(status)},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"connection_status": string(status)})
}

// --- Access management ---

type grantObjectStorageAccessRequest struct {
	UserID      string   `json:"user_id"`
	Permissions []string `json:"permissions"`
}

// GrantAccess handles POST /api/object-storage/:id/access (admin-only).
func (h *ObjectStorageHandler) GrantAccess(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageView)
	if !ok {
		return
	}
	var req grantObjectStorageAccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	targetUserID, err := uuid.Parse(req.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user_id")
		return
	}
	if err := h.access.GrantObjectStorageAccess(r.Context(), targetUserID, os.ResourceID, req.Permissions); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditObjectStorageAccessGranted, ResourceType: "OBJECT_STORAGE", ResourceID: &os.ResourceID,
		Metadata: map[string]any{"target_user_id": targetUserID.String(), "permissions": req.Permissions},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"granted": true})
}

// RevokeAccess handles DELETE /api/object-storage/:id/access/:userId (admin-only).
func (h *ObjectStorageHandler) RevokeAccess(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageView)
	if !ok {
		return
	}
	targetUserID, err := uuid.Parse(r.PathValue("userId"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if err := h.access.RevokeObjectStorageAccess(r.Context(), targetUserID, os.ResourceID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to revoke access")
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditObjectStorageAccessRevoked, ResourceType: "OBJECT_STORAGE", ResourceID: &os.ResourceID,
		Metadata: map[string]any{"target_user_id": targetUserID.String()},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

type objectStorageAccessMemberResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	View         bool   `json:"view"`
	Monitor      bool   `json:"monitor"`
	Browser      bool   `json:"browser"`
	Download     bool   `json:"download"`
	AccessSource string `json:"access_source"`
}

// ListAccess handles GET /api/object-storage/:id/access: the "Authorized
// Members" list on the object storage detail page (Step 18), merging
// direct grants with the storage's group members -- mirrors
// VMHandler.ListAccess's response shape exactly (`{"members": [...]}`),
// admin-only like GrantAccess/RevokeAccess above.
func (h *ObjectStorageHandler) ListAccess(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageView)
	if !ok {
		return
	}

	entries, err := h.service.ListAccess(r.Context(), os.ResourceID)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	members := make([]objectStorageAccessMemberResponse, 0, len(entries))
	for _, e := range entries {
		var view, monitor, browser, download bool
		for _, p := range e.Permissions {
			switch p {
			case services.PermObjectStorageView:
				view = true
			case services.PermObjectStorageMonitor:
				monitor = true
			case services.PermObjectStorageBrowser:
				browser = true
			case services.PermObjectStorageDownload:
				download = true
			}
		}
		members = append(members, objectStorageAccessMemberResponse{
			ID: e.UserID.String(), Name: e.Name, Email: e.Email,
			View: view, Monitor: monitor, Browser: browser, Download: download,
			AccessSource: string(e.Source),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"members": members})
}
