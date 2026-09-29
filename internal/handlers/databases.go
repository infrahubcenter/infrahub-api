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

// DatabaseHandler implements the standalone database CRUD/monitoring API
// (spec §5-10/§50-57): a database is a first-class resource under a
// Project (optionally a Group) -- never a VM child. Every database-scoped
// endpoint verifies the requested database actually exists and that the
// caller holds the required permission on its owning resource
// (spec §57's "do not trust database ID from frontend"), 404-not-403 on
// any failure.
type DatabaseHandler struct {
	store             *repository.Store
	authz             *services.AuthorizationService
	access            *services.AccessService
	databases         *services.DatabaseService
	metricsScheduler  *services.DatabaseMetricsScheduler
	connections       *directConnectionTester
	credentials       *services.StandaloneDatabaseCredentialService
	cache             *services.DatabaseMetricsCache
	deepCache         *services.DatabaseDeepMetricsCache
	fastThresholds    services.DatabaseHealthThresholds
	perfThresholds    services.DatabasePerformanceThresholds
	audit             *services.AuditService
	staleAfter        time.Duration
	streamInterval    time.Duration
	connectionTimeout time.Duration
	commandTimeout    time.Duration
	frontendOrigin    string
}

// directConnectionTester wraps DirectDatabaseConnection dialing so the
// handler never needs to know about credential decryption directly.
type directConnectionTester struct {
	credentials       *services.StandaloneDatabaseCredentialService
	connectionTimeout time.Duration
	commandTimeout    time.Duration
}

// NewDatabaseHandler creates a DatabaseHandler.
func NewDatabaseHandler(
	store *repository.Store, authz *services.AuthorizationService, access *services.AccessService, databases *services.DatabaseService,
	metricsScheduler *services.DatabaseMetricsScheduler, credentials *services.StandaloneDatabaseCredentialService,
	cache *services.DatabaseMetricsCache, deepCache *services.DatabaseDeepMetricsCache,
	fastThresholds services.DatabaseHealthThresholds, perfThresholds services.DatabasePerformanceThresholds, audit *services.AuditService,
	staleAfter, streamInterval, connectionTimeout, commandTimeout time.Duration, frontendOrigin string,
) *DatabaseHandler {
	return &DatabaseHandler{
		store: store, authz: authz, access: access, databases: databases, metricsScheduler: metricsScheduler,
		connections: &directConnectionTester{credentials: credentials, connectionTimeout: connectionTimeout, commandTimeout: commandTimeout},
		credentials: credentials, cache: cache, deepCache: deepCache, fastThresholds: fastThresholds, perfThresholds: perfThresholds,
		audit: audit, staleAfter: staleAfter, streamInterval: streamInterval,
		connectionTimeout: connectionTimeout, commandTimeout: commandTimeout, frontendOrigin: frontendOrigin,
	}
}

// authorizeDatabase resolves :id and verifies the caller holds
// requiredPermission on the database's owning resource -- 404-not-403 on
// any failure, mirroring DatabaseBrowserHandler.authorizeDatabase exactly.
func (h *DatabaseHandler) authorizeDatabase(w http.ResponseWriter, r *http.Request, requiredPermission string) (generated.Database, bool) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return generated.Database{}, false
	}
	databaseID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "database not found")
		return generated.Database{}, false
	}
	db, err := h.store.GetDatabaseByID(r.Context(), databaseID)
	if err != nil || db.DeletedAt.Valid {
		httpx.WriteError(w, http.StatusNotFound, "database not found")
		return generated.Database{}, false
	}
	allowed, err := h.authz.CanAccessDatabase(r.Context(), user, db.ResourceID, requiredPermission)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return generated.Database{}, false
	}
	if !allowed {
		httpx.WriteError(w, http.StatusNotFound, "database not found")
		return generated.Database{}, false
	}
	return db, true
}

// --- DTOs ---

type databaseDTO struct {
	ID                   string  `json:"id"`
	ResourceID           string  `json:"resource_id"`
	Name                 string  `json:"name,omitempty"`
	WorkspaceName        string  `json:"workspace_name,omitempty"`
	Type                 string  `json:"type"`
	Provider             string  `json:"provider,omitempty"`
	Host                 string  `json:"host"`
	Port                 int32   `json:"port"`
	DatabaseName         string  `json:"database_name,omitempty"`
	Region               string  `json:"region,omitempty"`
	ClusterIdentifier    string  `json:"cluster_identifier,omitempty"`
	Endpoint             string  `json:"endpoint,omitempty"`
	MonitoringEnabled    bool    `json:"monitoring_enabled"`
	ConnectionStatus     string  `json:"connection_status"`
	TLSEnabled           bool    `json:"tls_enabled"`
	TLSSkipVerify        bool    `json:"tls_skip_verify"`
	LastMetricsAt        *string `json:"last_metrics_at,omitempty"`
	CredentialUsername   string  `json:"credential_username,omitempty"`
	CredentialConfigured bool    `json:"credential_configured"`
}

// toDatabaseDTO never includes a password/secret/connection string (spec
// §8/§84) -- only whether a credential exists, and its username.
func (h *DatabaseHandler) toDatabaseDTO(r *http.Request, db generated.Database) databaseDTO {
	dto := databaseDTO{
		ID: db.ID.String(), ResourceID: db.ResourceID.String(), Type: db.Type, Provider: pgutil.TextOrEmpty(db.Provider),
		Host: db.Host, Port: db.Port, DatabaseName: pgutil.TextOrEmpty(db.DatabaseName), Region: pgutil.TextOrEmpty(db.Region),
		ClusterIdentifier: pgutil.TextOrEmpty(db.ClusterIdentifier), Endpoint: pgutil.TextOrEmpty(db.Endpoint),
		MonitoringEnabled: db.MonitoringEnabled, ConnectionStatus: db.ConnectionStatus, TLSEnabled: db.TlsEnabled, TLSSkipVerify: db.TlsSkipVerify,
		LastMetricsAt: formatTimestamptz(db.LastMetricsAt),
	}
	if username, configured := h.credentials.HasCredential(r.Context(), db.ID); configured {
		dto.CredentialUsername = username
		dto.CredentialConfigured = true
	}
	return dto
}

// List handles GET /api/databases -- scoped to the caller's authorized
// databases exactly like GET /api/databases/summary.
func (h *DatabaseHandler) List(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var resourceIDs []uuid.UUID
	if !user.IsAdmin() {
		access, err := h.authz.GetUserDatabaseAccess(r.Context(), user)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
			return
		}
		resourceIDs = make([]uuid.UUID, 0, len(access))
		for _, a := range access {
			resourceIDs = append(resourceIDs, a.ResourceID)
		}
	}
	rows, err := h.store.ListStandaloneDatabasesForDashboard(r.Context(), resourceIDs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load databases")
		return
	}
	items := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		items = append(items, map[string]any{
			"id": row.ID.String(), "resource_id": row.ResourceID.String(), "name": pgutil.TextOrEmpty(row.ResourceName),
			"workspace_id": pgutil.UUIDPtr(row.WorkspaceID), "workspace_name": pgutil.TextOrEmpty(row.WorkspaceName),
			"type": row.Type, "provider": pgutil.TextOrEmpty(row.Provider),
			"host": row.Host, "port": row.Port, "database_name": pgutil.TextOrEmpty(row.DatabaseName),
			"monitoring_enabled": row.MonitoringEnabled, "connection_status": row.ConnectionStatus,
			"health": row.LatestHealth, "last_metric_at": formatTimestamptz(row.LatestMetricAt),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"databases": items, "total": len(items)})
}

// Get handles GET /api/databases/:id.
func (h *DatabaseHandler) Get(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseView)
	if !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.enrichedDatabaseDTO(r, db))
}

type monitoringHealthTierDTO struct {
	Tier             string  `json:"tier"`
	LastSuccessAt    *string `json:"last_success_at,omitempty"`
	LastFailureAt    *string `json:"last_failure_at,omitempty"`
	LastError        string  `json:"last_error,omitempty"`
	MetricsCollected int64   `json:"metrics_collected"`
}

// MonitoringHealth handles GET /api/databases/{id}/monitoring-health --
// surfaces *why* Performance/Metrics might be empty even with monitoring
// enabled (bad credential, connection refused, insufficient privileges):
// the schedulers already record this per cycle
// (RecordStandaloneDatabaseMonitoringFailure/Success,
// database_deep_metrics_service.go/database_metrics_service.go) but
// nothing read it back before this endpoint existed -- a collector that
// fails silently every cycle previously looked identical, forever, to
// one that's simply never been enqueued.
func (h *DatabaseHandler) MonitoringHealth(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseView)
	if !ok {
		return
	}
	rows, err := h.store.ListStandaloneDatabaseMonitoringHealth(r.Context(), db.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load monitoring health")
		return
	}
	tiers := make([]monitoringHealthTierDTO, 0, len(rows))
	for _, row := range rows {
		tiers = append(tiers, monitoringHealthTierDTO{
			Tier: row.Tier, LastSuccessAt: formatTimestamptz(row.LastSuccessAt), LastFailureAt: formatTimestamptz(row.LastFailureAt),
			LastError: pgutil.TextOrEmpty(row.LastError), MetricsCollected: row.MetricsCollected,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"tiers": tiers})
}

// enrichedDatabaseDTO adds the resource's display name and owning
// workspace's name (not carried on the bare `databases` row) -- best
// effort, since a caller reaching this from Configure/Update already
// knows both and a lookup failure shouldn't turn a successful write into
// an error response.
func (h *DatabaseHandler) enrichedDatabaseDTO(r *http.Request, db generated.Database) databaseDTO {
	dto := h.toDatabaseDTO(r, db)
	if detail, err := h.store.GetDatabaseWithResourceByID(r.Context(), db.ID); err == nil {
		dto.Name = detail.ResourceName
		dto.WorkspaceName = detail.WorkspaceName
	}
	return dto
}

// permissionsForDatabase computes the caller-scoped permissions array for
// a database resource -- mirrors ObjectStorageHandler.permissionsForObjectStorage
// exactly (Step 17 Phase 5's My Access integration needs the same
// per-user-scoped permissions field for databases that object storage's
// List endpoint already computes for object storages): an Admin gets all
// five grantable database permissions implicitly (Admin never needs an
// explicit grant), a Member gets whatever EffectiveDatabaseAccess resolves.
func (h *DatabaseHandler) permissionsForDatabase(r *http.Request, user services.AuthenticatedUser, resourceID uuid.UUID) []string {
	if user.IsAdmin() {
		return []string{
			services.PermDatabaseView, services.PermDatabasePerformance,
			services.PermDatabaseBrowser, services.PermDatabaseLogs, services.PermDatabaseQueryDetails,
		}
	}
	access, err := h.authz.EffectiveDatabaseAccess(r.Context(), user.ID, resourceID)
	if err != nil || access == nil {
		return []string{}
	}
	return access.Permissions
}

type configureDatabaseRequest struct {
	WorkspaceID       string `json:"workspace_id"`
	Name              string `json:"name"`
	Type              string `json:"type"`
	Provider          string `json:"provider,omitempty"`
	Host              string `json:"host"`
	Port              int32  `json:"port"`
	DatabaseName      string `json:"database_name,omitempty"`
	Region            string `json:"region,omitempty"`
	ClusterIdentifier string `json:"cluster_identifier,omitempty"`
	Endpoint          string `json:"endpoint,omitempty"`
	TLSEnabled        bool   `json:"tls_enabled"`
	TLSSkipVerify     bool   `json:"tls_skip_verify"`
	Username          string `json:"username,omitempty"`
	Password          string `json:"password,omitempty"`
}

// Configure handles POST /api/databases (admin-only, spec §6): manual
// connection of a standalone database. Never accepts a "query"/"command"
// field.
func (h *DatabaseHandler) Configure(w http.ResponseWriter, r *http.Request) {
	var req configureDatabaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	workspaceID, err := uuid.Parse(req.WorkspaceID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid workspace_id")
		return
	}

	db, err := h.databases.Configure(r.Context(), services.ConfigureInput{
		WorkspaceID: workspaceID, Name: req.Name, Type: req.Type, Provider: req.Provider,
		Host: req.Host, Port: req.Port, DatabaseName: req.DatabaseName, Region: req.Region,
		ClusterIdentifier: req.ClusterIdentifier, Endpoint: req.Endpoint, TLSEnabled: req.TLSEnabled, TLSSkipVerify: req.TLSSkipVerify,
		Username: req.Username, Password: req.Password,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditDatabaseCreated, ResourceType: "DATABASE", ResourceID: &db.ResourceID,
		Metadata: map[string]any{"type": db.Type},
	})
	httpx.WriteJSON(w, http.StatusCreated, h.enrichedDatabaseDTO(r, db))
}

type updateDatabaseRequest struct {
	Type              *string `json:"type,omitempty"`
	Host              *string `json:"host,omitempty"`
	Port              *int32  `json:"port,omitempty"`
	DatabaseName      *string `json:"database_name,omitempty"`
	Provider          *string `json:"provider,omitempty"`
	Region            *string `json:"region,omitempty"`
	ClusterIdentifier *string `json:"cluster_identifier,omitempty"`
	Endpoint          *string `json:"endpoint,omitempty"`
	TLSEnabled        *bool   `json:"tls_enabled,omitempty"`
	TLSSkipVerify     *bool   `json:"tls_skip_verify,omitempty"`
	Username          *string `json:"username,omitempty"`
	Password          *string `json:"password,omitempty"`
	MonitoringEnabled *bool   `json:"monitoring_enabled,omitempty"`
}

// Update handles PATCH /api/databases/:id (admin-only).
func (h *DatabaseHandler) Update(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseView)
	if !ok {
		return
	}
	var req updateDatabaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	updated, err := h.databases.Update(r.Context(), db.ID, services.UpdateInput{
		Type: req.Type, Host: req.Host, Port: req.Port, DatabaseName: req.DatabaseName, Provider: req.Provider,
		Region: req.Region, ClusterIdentifier: req.ClusterIdentifier, Endpoint: req.Endpoint,
		TLSEnabled: req.TLSEnabled, TLSSkipVerify: req.TLSSkipVerify,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Username != nil || req.Password != nil {
		username, password := "", ""
		if req.Username != nil {
			username = *req.Username
		}
		if req.Password != nil {
			password = *req.Password
		}
		if err := h.credentials.SetCredential(r.Context(), db.ID, username, password); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to save credential")
			return
		}
	}
	if req.MonitoringEnabled != nil {
		updated, err = h.databases.SetMonitoringEnabled(r.Context(), db.ID, *req.MonitoringEnabled)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to update monitoring state")
			return
		}
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{UserID: &actor.ID, Action: services.AuditDatabaseUpdated, ResourceType: "DATABASE", ResourceID: &updated.ResourceID})
	httpx.WriteJSON(w, http.StatusOK, h.enrichedDatabaseDTO(r, updated))
}

// Delete handles DELETE /api/databases/:id (admin-only, spec §82):
// soft-deletes the monitoring configuration only -- never drops the real
// external database. Step 22: now requires the resource's exact current
// name as confirmation_name, validated server-side against the canonical
// resources.name -- previously this deleted immediately with no
// confirmation check at all.
func (h *DatabaseHandler) Delete(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseView)
	if !ok {
		return
	}
	var req deleteConfirmationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	resource, err := h.store.GetResourceByID(r.Context(), db.ResourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "database not found")
		return
	}
	if req.ConfirmationName != resource.Name {
		httpx.WriteError(w, http.StatusBadRequest, services.ErrConfirmationMismatch.Error())
		return
	}
	if err := h.databases.Delete(r.Context(), db.ID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to delete database")
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditDatabaseDeleted, ResourceType: "DATABASE", ResourceID: &db.ResourceID,
		Metadata: map[string]any{"name": resource.Name},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// Test handles POST /api/databases/:id/test (admin-only, spec §7): runs
// exactly one backend-defined, hardcoded read-only probe -- never
// accepts a client-supplied query of any kind.
func (h *DatabaseHandler) Test(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseView)
	if !ok {
		return
	}
	username, password, err := h.credentials.GetCredential(r.Context(), db.ID)
	status := services.ConnUNAVAILABLE
	if err == nil {
		conn := services.DirectDatabaseConnection{
			Type: services.DatabaseType(db.Type), Host: db.Host, Port: int(db.Port), Username: username, Password: password,
			Database: pgutil.TextOrEmpty(db.DatabaseName), TLSEnabled: db.TlsEnabled, TLSSkipVerify: db.TlsSkipVerify,
			ConnectTimeout: h.connectionTimeout, QueryTimeout: h.commandTimeout,
		}
		testErr := services.TestDirectConnection(r.Context(), conn)
		status = services.ConnectionStatusFromError(testErr)
	}
	_, _ = h.store.UpdateDatabaseConnectionStatus(r.Context(), generated.UpdateDatabaseConnectionStatusParams{ID: db.ID, ConnectionStatus: string(status)})

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditDatabaseConnectionTested, ResourceType: "DATABASE", ResourceID: &db.ResourceID,
		Metadata: map[string]any{"connection_status": string(status)},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"connection_status": string(status)})
}

// --- Access management (spec §51/#91-94) ---

type grantDatabaseAccessRequest struct {
	UserID      string   `json:"user_id"`
	Permissions []string `json:"permissions"`
}

// GrantAccess handles POST /api/databases/:id/access (admin-only).
func (h *DatabaseHandler) GrantAccess(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseView)
	if !ok {
		return
	}
	var req grantDatabaseAccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	targetUserID, err := uuid.Parse(req.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user_id")
		return
	}
	if err := h.access.GrantDatabaseAccess(r.Context(), targetUserID, db.ResourceID, req.Permissions); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditDatabaseAccessGranted, ResourceType: "DATABASE", ResourceID: &db.ResourceID,
		Metadata: map[string]any{"target_user_id": targetUserID.String(), "permissions": req.Permissions},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"granted": true})
}

// RevokeAccess handles DELETE /api/databases/:id/access/:userId (admin-only).
func (h *DatabaseHandler) RevokeAccess(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseView)
	if !ok {
		return
	}
	targetUserID, err := uuid.Parse(r.PathValue("userId"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if err := h.access.RevokeDatabaseAccess(r.Context(), targetUserID, db.ResourceID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to revoke access")
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditDatabaseAccessRevoked, ResourceType: "DATABASE", ResourceID: &db.ResourceID,
		Metadata: map[string]any{"target_user_id": targetUserID.String()},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

type databaseAccessMemberResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	View         bool   `json:"view"`
	Performance  bool   `json:"performance"`
	Browser      bool   `json:"browser"`
	Logs         bool   `json:"logs"`
	QueryDetails bool   `json:"query_details"`
	AccessSource string `json:"access_source"`
}

// ListAccess handles GET /api/databases/:id/access: the "Authorized
// Members" list on the database detail page (Step 18), merging direct
// grants with the database's group members -- mirrors
// VMHandler.ListAccess's response shape exactly (`{"members": [...]}`),
// admin-only like GrantAccess/RevokeAccess above.
func (h *DatabaseHandler) ListAccess(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseView)
	if !ok {
		return
	}

	entries, err := h.databases.ListAccess(r.Context(), db.ResourceID)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	members := make([]databaseAccessMemberResponse, 0, len(entries))
	for _, e := range entries {
		var view, performance, browser, logs, queryDetails bool
		for _, p := range e.Permissions {
			switch p {
			case services.PermDatabaseView:
				view = true
			case services.PermDatabasePerformance:
				performance = true
			case services.PermDatabaseBrowser:
				browser = true
			case services.PermDatabaseLogs:
				logs = true
			case services.PermDatabaseQueryDetails:
				queryDetails = true
			}
		}
		members = append(members, databaseAccessMemberResponse{
			ID: e.UserID.String(), Name: e.Name, Email: e.Email,
			View: view, Performance: performance, Browser: browser, Logs: logs, QueryDetails: queryDetails,
			AccessSource: string(e.Source),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"members": members})
}
