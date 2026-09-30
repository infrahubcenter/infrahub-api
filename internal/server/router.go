// Package server builds the HTTP router: it wires handlers, middleware, and
// routes together. Extracted from cmd/server/main.go so integration tests
// can stand up the exact same router against a real database instead of
// duplicating the route table.
package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"vmcontrolcenter/backend/internal/handlers"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/middleware"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// Dependencies are the services and configuration NewRouter needs. All
// fields are required except Logger, which defaults to slog.Default().
type Dependencies struct {
	Pool *pgxpool.Pool
	// Plan limits (see services.LicenseService). Nil means no limits, as in
	// tests that don't exercise them.
	License              *services.LicenseService
	Store                *repository.Store
	Tokens               *services.TokenService
	Auth                 *services.AuthService
	OAuthRedirectBaseURL string
	AppBaseURL           string
	Authz                *services.AuthorizationService
	Audit                *services.AuditService
	Workspaces           *services.WorkspaceService
	Resources            *services.ResourceService
	VMs                  *services.VMService
	Access               *services.AccessService
	SSHKeyCredentials    *services.SSHKeyCredentialService
	HostKeys             *services.HostKeyService
	SSH                  *services.SSHService
	Discovery            *services.VMDiscoveryService
	SSHConnectTimeout    time.Duration
	MonitorScheduler     *services.MonitoringScheduler
	MonitorStaleAfter    time.Duration
	Packages             *services.PackageService
	PackageScheduler     *services.PackageScanScheduler
	ExternalPackages     *services.ExternalPackageScanner
	SMTPTimeout          time.Duration
	DockerScheduler      *services.DockerDiscoveryScheduler
	DockerMetricsCache   *services.DockerMetricsCache
	DockerStaleAfter     time.Duration
	DockerStreamInterval time.Duration
	// The top-level Docker Monitoring/Logs section's Workspace-scoped
	// view-only access grants (also reused by K8s permissions -- see
	// services.DockerAccessService's doc comment).
	DockerAccess *services.DockerAccessService
	// Standalone Kubernetes clusters (Admin-only setup) plus the top-level
	// K8s Monitoring/Logs section reusing DockerAccess above for its
	// Workspace-scoped grants. K8sAgentHub/K8sAgentTokens back the
	// in-cluster agent model (no kubeconfig is ever accepted or stored --
	// see services/k8s_credential.go's doc comment).
	K8sClusters    *services.K8sClusterService
	K8sAgentHub    *services.K8sAgentHub
	K8sAgentTokens *services.K8sAgentTokenService
	K8s            *services.K8sService
	K8sScheduler   *services.K8sDiscoveryScheduler
	// This backend's own externally-reachable WebSocket URL for the
	// in-cluster agent to dial (K8S_AGENT_BACKEND_URL) -- handed back on
	// Configure/RegenerateAgentToken so the Connect Cluster screen shows a
	// real, usable backend-url instead of one derived from the browser's
	// own (often localhost-only) API base. Empty if unconfigured.
	K8sAgentBackendURL string
	// Per-VM Docker agent (Docker+Kubernetes monitoring rework, Phase 1) --
	// mirrors K8sAgentHub/K8sAgentTokens/K8s's shape exactly, but install is
	// a single automated SSH-based action (DockerAgentInstall) rather than
	// a manifest the admin applies by hand.
	DockerAgentHub     *services.DockerAgentHub
	DockerAgentTokens  *services.DockerAgentTokenService
	DockerAgent        *services.DockerAgentService
	DockerAgentInstall *services.DockerAgentInstallService
	// VM Agent: a separate, push-based agent (migrations/052_vm_agent.sql)
	// running alongside the existing SSH-based monitoring scheduler, never
	// replacing it -- see services/vm_agent_hub.go's doc comment for the
	// metrics_push design. No automated SSH install path exists (see
	// services/vm_agent_install.go's doc comment) -- VMAgentInstall here
	// only exposes the backend URL/run-command builder for the manual
	// Connect VM / regenerate-token flows.
	VMAgentHub     *services.VMAgentHub
	VMAgentTokens  *services.VMAgentTokenService
	VMAgent        *services.VMAgentService
	VMAgentInstall *services.VMAgentInstallService
	// Docker Hosts: a standalone Docker agent target with no VM record and
	// no SSH at all, mirroring K8sClusters/K8sAgentTokens above exactly --
	// shares DockerAgentHub with VM-attached agents (see
	// services/docker_host.go's doc comment).
	DockerHosts           *services.DockerHostService
	DockerHostAgentTokens *services.DockerHostAgentTokenService
	// Log history: how far back Search may look -- handlers clamp
	// client-supplied from/to to this window (see docker_log_capture.go/
	// k8s_log_capture.go for the background capture that fills it).
	DockerLogRetention time.Duration
	K8sLogRetention    time.Duration
	// Monitoring/Logs Folder > Dashboard: four independent trees under
	// Workspace (Monitoring>Docker, Monitoring>Kubernetes, Logs>Docker,
	// Logs>Kubernetes), each Dashboard binding one VM/K8sCluster plus a
	// multi-resource selection (see services/monitoring_dashboards.go).
	// Also grantable directly (FOLDER/DASHBOARD scope) via
	// DockerAccessService.Grant, alongside the existing Workspace/Resource
	// scopes.
	MonitoringFolders              *services.MonitoringFolderService
	MonitoringDashboards           *services.MonitoringDashboardService
	UpdatePlans                    *services.UpdatePlanService
	OSUpdates                      *services.OSUpdateService
	UpdateExecution                *services.UpdateExecutionService
	UpdateWorker                   *services.UpdateExecutionWorker
	RebootExecution                *services.RebootExecutionService
	RebootWorker                   *services.RebootExecutionWorker
	Databases                      *services.DatabaseService
	DatabaseMetricsScheduler       *services.DatabaseMetricsScheduler
	DatabaseDeepMetricsScheduler   *services.DatabaseDeepMetricsScheduler
	DatabaseCredentials            *services.StandaloneDatabaseCredentialService
	DatabaseMetricsCache           *services.DatabaseMetricsCache
	DatabaseDeepMetricsCache       *services.DatabaseDeepMetricsCache
	DatabaseFastThresholds         services.DatabaseHealthThresholds
	DatabasePerfThresholds         services.DatabasePerformanceThresholds
	DatabaseStaleAfter             time.Duration
	DatabaseStreamInterval         time.Duration
	DatabaseConnectTimeout         time.Duration
	DatabaseCommandTimeout         time.Duration
	DatabaseBrowser                *services.DatabaseBrowserService
	DatabaseConnectionLimiter      *services.DatabaseConnectionLimiter
	DatabaseOperations             *services.DatabaseOperationService
	DatabaseOperationWorker        *services.DatabaseOperationWorker
	Alerts                         *services.AlertService
	AlertRules                     *services.AlertRuleService
	NotificationPolicies           *services.NotificationPolicyService
	Notifications                  *services.NotificationService
	AlertStreamInterval            time.Duration
	ObjectStorages                 *services.ObjectStorageService
	ObjectStorageCredentials       *services.StandaloneObjectStorageCredentialService
	ObjectStorageMetricsCache      *services.ObjectStorageMetricsCache
	ObjectStorageConnectionTimeout time.Duration
	ObjectStorageBrowser           *services.ObjectStorageBrowserService
	ObjectStorageMaxPageSize       int32
	ObjectStoragePreviewMaxBytes   int64
	ObjectStorageDownloadURLTTL    time.Duration
	CookieSecure                   bool
	FrontendOrigin                 string
	// ProxyKey (INFRAHUB_PROXY_KEY): see middleware.RequireProxyKey.
	ProxyKey               string
	MaxRequestBodyBytes    int64
	LoginRateLimitAttempts int32
	LoginRateLimitWindow   time.Duration
	// Step 21: Operations/Audit Logs/Settings.
	AuditQuery       *services.AuditQueryService
	UserPreferences  *services.UserPreferencesService
	PlatformConfig   handlers.PlatformConfigView
	PlatformSettings *services.PlatformSettingsService
	Logger           *slog.Logger
}

// NewRouter builds the full API router: every route from the Step 3/4
// spec, wrapped in the appropriate authentication/authorization
// middleware, plus CORS, request logging, and panic recovery.
func NewRouter(deps Dependencies) http.Handler {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	healthHandler := handlers.NewHealthHandler(deps.Pool)
	authHandler := handlers.NewAuthHandler(deps.Auth, deps.Audit, deps.CookieSecure)
	oauthHandler := handlers.NewOAuthHandler(deps.PlatformSettings, deps.OAuthRedirectBaseURL, deps.Auth, deps.Audit, deps.CookieSecure, deps.AppBaseURL)
	accessHandler := handlers.NewAccessHandler(deps.Access, deps.Audit)
	vmHandler := handlers.NewVMHandler(deps.VMs, deps.Audit)
	workspaceHandler := handlers.NewWorkspaceHandler(deps.Workspaces, deps.Audit)
	resourceHandler := handlers.NewResourceHandler(deps.Resources)
	sshHandler := handlers.NewSSHHandler(deps.Store, deps.Authz, deps.HostKeys, deps.SSH, deps.Discovery, deps.Audit, deps.SSHConnectTimeout)
	sshKeyCredentialHandler := handlers.NewSSHKeyCredentialHandler(deps.SSHKeyCredentials, deps.Audit)
	vmConsoleHandler := handlers.NewVMConsoleHandler(deps.Store, deps.Authz, deps.SSH, deps.Audit, deps.FrontendOrigin)
	monitoringHandler := handlers.NewMonitoringHandler(deps.Store, deps.Authz, deps.MonitorScheduler, deps.Audit, deps.MonitorStaleAfter)
	packageHandler := handlers.NewPackageHandler(deps.Store, deps.Authz, deps.Packages, deps.PackageScheduler, deps.ExternalPackages, deps.Audit)
	recommendationHandler := handlers.NewRecommendationHandler(deps.Store, deps.Authz)
	dockerHandler := handlers.NewDockerHandler(deps.Store, deps.Authz, deps.DockerScheduler, deps.DockerMetricsCache, deps.Audit, deps.DockerStaleAfter, deps.DockerStreamInterval, deps.FrontendOrigin)
	dockerAccessHandler := handlers.NewDockerAccessHandler(deps.Store, deps.DockerAccess, deps.Audit)
	dockerLogsHandler := handlers.NewDockerLogsHandler(deps.Store, deps.Authz, deps.SSH, deps.Audit, deps.FrontendOrigin, deps.DockerLogRetention)
	k8sHandler := handlers.NewK8sHandler(deps.Store, deps.K8sClusters, deps.K8sAgentTokens, deps.K8s, deps.K8sScheduler, deps.Audit, deps.K8sAgentBackendURL)
	k8sAgentHandler := handlers.NewK8sAgentHandler(deps.K8sAgentHub, deps.K8sAgentTokens)
	dockerAgentHandler := handlers.NewDockerAgentHandler(
		deps.Store, deps.DockerAgentHub, deps.DockerAgentTokens, deps.DockerHostAgentTokens, deps.DockerAgent, deps.DockerAgentInstall, deps.Audit,
		deps.FrontendOrigin,
	)
	vmAgentHandler := handlers.NewVMAgentHandler(deps.Store, deps.VMs, deps.VMAgentHub, deps.VMAgentTokens, deps.VMAgent, deps.VMAgentInstall, deps.Audit, deps.FrontendOrigin)
	vmAgentMetricsHandler := handlers.NewVMAgentMetricsHandler(deps.Store, deps.Authz, deps.VMAgent, deps.FrontendOrigin)
	vmAgentLogsHandler := handlers.NewVMAgentLogsHandler(deps.Store, deps.Authz, deps.VMAgent, deps.Audit, deps.FrontendOrigin)
	dockerHostHandler := handlers.NewDockerHostHandler(
		deps.Store, deps.DockerHosts, deps.DockerHostAgentTokens, deps.DockerAgentHub, deps.DockerAgent, deps.Authz,
		deps.Audit, deps.DockerAgentInstall.BackendURL(), deps.FrontendOrigin, deps.DockerLogRetention,
	)
	k8sOverviewHandler := handlers.NewK8sOverviewHandler(deps.Store, deps.Authz, deps.K8s)
	k8sLogsHandler := handlers.NewK8sLogsHandler(deps.Store, deps.Authz, deps.K8s, deps.Audit, deps.FrontendOrigin, deps.K8sLogRetention)
	monitoringDashboardsHandler := handlers.NewMonitoringDashboardsHandler(deps.Store, deps.MonitoringFolders, deps.MonitoringDashboards, deps.Audit)
	updatesHandler := handlers.NewUpdatesHandler(deps.Store, deps.Authz, deps.UpdatePlans, deps.PackageScheduler, deps.OSUpdates, deps.Audit)
	updateOperationsHandler := handlers.NewUpdateOperationsHandler(deps.Store, deps.Authz, deps.UpdateExecution, deps.UpdateWorker, deps.Audit, deps.FrontendOrigin)
	rebootOperationsHandler := handlers.NewRebootOperationsHandler(deps.Store, deps.Authz, deps.RebootExecution, deps.RebootWorker, deps.Audit, deps.FrontendOrigin)
	databaseHandler := handlers.NewDatabaseHandler(
		deps.Store, deps.Authz, deps.Access, deps.Databases, deps.DatabaseMetricsScheduler, deps.DatabaseCredentials,
		deps.DatabaseMetricsCache, deps.DatabaseDeepMetricsCache, deps.DatabaseFastThresholds, deps.DatabasePerfThresholds,
		deps.Audit, deps.DatabaseStaleAfter, deps.DatabaseStreamInterval, deps.DatabaseConnectTimeout, deps.DatabaseCommandTimeout, deps.FrontendOrigin,
	)
	databaseBrowserHandler := handlers.NewDatabaseBrowserHandler(deps.Store, deps.DatabaseBrowser, deps.Authz)
	databaseOperationsHandler := handlers.NewDatabaseOperationsHandler(deps.Store, deps.DatabaseOperations, deps.DatabaseOperationWorker, deps.Audit, deps.FrontendOrigin)
	alertsHandler := handlers.NewAlertsHandler(deps.Store, deps.Authz, deps.Alerts, deps.Audit, deps.AlertStreamInterval, deps.FrontendOrigin)
	alertRulesHandler := handlers.NewAlertRulesHandler(deps.Store, deps.AlertRules, deps.Audit)
	notificationsHandler := handlers.NewNotificationsHandler(deps.Store)
	notificationPoliciesHandler := handlers.NewNotificationPoliciesHandler(deps.Store, deps.NotificationPolicies, deps.Notifications, deps.Audit)
	objectStorageHandler := handlers.NewObjectStorageHandler(
		deps.Store, deps.Authz, deps.Access, deps.ObjectStorages, deps.ObjectStorageCredentials, deps.ObjectStorageMetricsCache, deps.Audit,
		deps.ObjectStorageConnectionTimeout, deps.ObjectStorageConnectionTimeout,
	)
	objectStorageBrowserHandler := handlers.NewObjectStorageBrowserHandler(
		deps.Store, deps.Authz, deps.ObjectStorageBrowser, deps.Audit,
		deps.ObjectStorageMaxPageSize, deps.ObjectStoragePreviewMaxBytes, deps.ObjectStorageDownloadURLTTL,
	)
	// Constructed after databaseHandler/objectStorageHandler (Step 17 Phase
	// 5) so it can reuse their unexported permissionsForDatabase/
	// permissionsForObjectStorage methods directly instead of
	// reimplementing permission resolution a third time.
	myAccessHandler := handlers.NewMyAccessHandler(deps.VMs, deps.Store, deps.Authz, databaseHandler, objectStorageHandler)
	// Step 19 Phase 2: the central monitoring dashboard's Overview/
	// Resources endpoints -- same "constructed after databaseHandler/
	// objectStorageHandler" constraint as myAccessHandler immediately
	// above, and for the identical reason (reuses their unexported
	// permissionsForDatabase/permissionsForObjectStorage methods via
	// scopedDatabaseAccess/scopedObjectStorageAccess rather than a third
	// permission-resolution implementation).
	monitoringDashboardHandler := handlers.NewMonitoringDashboardHandler(deps.Store, deps.Authz, deps.VMs, databaseHandler, objectStorageHandler)
	// Step 18 Phase 3: same "constructed after databaseHandler/
	// objectStorageHandler" constraint as myAccessHandler above --
	// GET /api/users/:id's new database_access/object_storage_access
	// fields need the same permissionsForDatabase/permissionsForObjectStorage
	// reuse.
	userHandler := handlers.NewUserHandler(deps.Store, deps.Auth, deps.VMs, deps.Authz, databaseHandler, objectStorageHandler, deps.Audit, deps.PlatformSettings, deps.AppBaseURL, deps.SMTPTimeout)
	// Step 18 Phase 2: unified Permissions page -- a thin read-only wrapper
	// over ListAllDirectResourceGrants, needing only the Store (no service
	// layer of its own, unlike every other handler here).
	permissionsHandler := handlers.NewPermissionsHandler(deps.Store)
	// Step 21: /audit-logs and /operations. Both are pure aggregation
	// layers over already-existing, already-tested data/authorization --
	// see internal/services/audit_query.go and internal/handlers/
	// operations.go's own doc comments for exactly what each reuses.
	auditLogsHandler := handlers.NewAuditLogsHandler(deps.AuditQuery)
	operationsHandler := handlers.NewOperationsHandler(deps.Store, deps.Authz)
	meSettingsHandler := handlers.NewMeSettingsHandler(deps.Auth, deps.UserPreferences, deps.Audit)
	platformSettingsHandler := handlers.NewPlatformSettingsHandler(deps.PlatformConfig, deps.PlatformSettings, deps.Audit)
	savedViewsHandler := handlers.NewSavedViewsHandler(deps.Store)

	requireAuth := middleware.RequireAuthentication(deps.Tokens, deps.Auth)
	// Owner is a strict superset of Admin (services.AuthenticatedUser.
	// IsAdmin() already reflects this) -- RequireAnyRole here means every
	// existing Admin-gated route below stays Owner-inclusive automatically,
	// with no change needed at any individual route.
	requireAdmin := func(next http.HandlerFunc) http.Handler {
		return requireAuth(middleware.RequireAnyRole(services.RoleAdmin, services.RoleOwner)(next))
	}
	authenticated := func(next http.HandlerFunc) http.Handler {
		return requireAuth(next)
	}
	// Refuses to add one more of kind past the plan's limit (403 with
	// code "plan_limit"), before the create handler runs.
	withinPlan := func(kind services.LimitKind, next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if deps.License != nil {
				if err := deps.License.CheckCanAdd(r.Context(), kind); err != nil {
					if services.IsPlanLimit(err) {
						httpx.WriteJSON(w, http.StatusForbidden, map[string]string{"error": err.Error(), "code": "plan_limit"})
						return
					}
					httpx.WriteError(w, http.StatusInternalServerError, "could not check plan limits")
					return
				}
			}
			next(w, r)
		}
	}
	// Re-enabling a disabled user counts against the user limit too.
	withinPlanReactivation := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			var req struct {
				IsActive *bool `json:"is_active"`
			}
			_ = json.Unmarshal(body, &req)
			if req.IsActive != nil && *req.IsActive {
				withinPlan(services.LimitUsers, next)(w, r)
				return
			}
			next(w, r)
		}
	}
	// Generic resources are created with a resource_type in the body.
	withinPlanResource := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			var req struct {
				ResourceType string `json:"resource_type"`
			}
			_ = json.Unmarshal(body, &req)
			kind := services.LimitDatabases
			if req.ResourceType == "OBJECT_STORAGE" {
				kind = services.LimitObjectStorage
			}
			withinPlan(kind, next)(w, r)
		}
	}
	// Owner-exclusive: editing sign-in-method configuration. An Admin can
	// still view the read-only status (GET /api/settings/platform stays
	// under requireAdmin above) but never edit it.
	requireOwner := func(next http.HandlerFunc) http.Handler {
		return requireAuth(middleware.RequireRole(services.RoleOwner)(next))
	}

	mux := http.NewServeMux()

	// Public.
	mux.HandleFunc("GET /api/health", healthHandler.Health)
	mux.HandleFunc("GET /api/live", healthHandler.Live)
	// Rate-limited per source IP (Step 20): login is the one unauthenticated
	// endpoint that accepts a secret guess, so it's the one endpoint here
	// that needs brute-force protection; refresh/logout require an
	// already-issued token/cookie and don't.
	loginLimiter := middleware.NewRateLimiter(int(deps.LoginRateLimitAttempts), deps.LoginRateLimitWindow)
	mux.HandleFunc("POST /api/auth/login", loginLimiter.LimitByIP(authHandler.Login))
	mux.HandleFunc("POST /api/auth/refresh", authHandler.Refresh)
	mux.HandleFunc("POST /api/auth/logout", authHandler.Logout)
	// OAuth login (GitHub/Google), invite-only -- public like /login above,
	// and rate-limited the same way since Callback triggers real outbound
	// HTTP (token exchange + userinfo fetch) per request.
	mux.HandleFunc("GET /api/auth/oauth/providers", oauthHandler.Providers)
	mux.HandleFunc("GET /api/auth/oauth/{provider}/start", loginLimiter.LimitByIP(oauthHandler.Start))
	mux.HandleFunc("GET /api/auth/oauth/{provider}/callback", loginLimiter.LimitByIP(oauthHandler.Callback))

	// Authenticated (any role) -- resource-level authorization, where it
	// applies, happens inside the handler via AuthorizationService/VMService.
	mux.Handle("GET /api/auth/me", authenticated(authHandler.Me))
	mux.Handle("POST /api/auth/ws-ticket", authenticated(handlers.WSTicket(deps.Tokens)))
	mux.Handle("GET /api/my-access", authenticated(myAccessHandler.Get))
	mux.Handle("GET /api/my-access/vms", authenticated(myAccessHandler.ListVMs))
	mux.Handle("GET /api/vms", authenticated(vmHandler.List))
	mux.Handle("GET /api/vms/{id}", authenticated(vmHandler.Get))

	// Step 19 Phase 2: the central monitoring dashboard. Authenticated any
	// role, like /api/my-access/api/alerts -- the response scoping inside
	// loadAuthorizedResources is the security boundary, not the route
	// gate. No /api/monitoring/resources/{id} (every resource type's own
	// detail page/API already exists) and no /api/monitoring/workspaces/{id}
	// (workspace scoping is the ?workspace_id= query param below instead).
	mux.Handle("GET /api/monitoring/overview", authenticated(monitoringDashboardHandler.Overview))
	mux.Handle("GET /api/monitoring/resources", authenticated(monitoringDashboardHandler.Resources))
	// Step 19 final phase: the dashboard's event timeline, composed from
	// Alerts + Recommendations timestamps (plan decision #7) -- no new
	// audit-log endpoint. Same authenticated-any-role/response-scoping
	// security boundary as the two routes above.
	mux.Handle("GET /api/monitoring/timeline", authenticated(monitoringDashboardHandler.Timeline))

	// Admin only: users.
	mux.Handle("GET /api/license", authenticated(handlers.License(deps.License)))
	mux.Handle("POST /api/users", requireAdmin(withinPlan(services.LimitUsers, userHandler.Create)))
	mux.Handle("GET /api/users", requireAdmin(userHandler.List))
	mux.Handle("GET /api/users/{id}", requireAdmin(userHandler.Get))
	mux.Handle("PATCH /api/users/{id}", requireAdmin(withinPlanReactivation(userHandler.Update)))
	mux.Handle("DELETE /api/users/{id}", requireAdmin(userHandler.Delete))
	mux.Handle("POST /api/users/{id}/vm-access", requireAdmin(accessHandler.GrantVMAccess))
	mux.Handle("DELETE /api/users/{id}/vm-access/{vmId}", requireAdmin(accessHandler.RevokeVMAccess))

	// Admin only: Step 18 Phase 2's unified Permissions page -- the
	// cross-resource-type direct-grant ledger (VM/Database/ObjectStorage in
	// one place). A pure role-gated category endpoint, not resource-scoped,
	// so it's a plain 403 via requireAdmin -- no 404-vs-403 IDOR question
	// applies here (plan decision #2).
	mux.Handle("GET /api/permissions", requireAdmin(permissionsHandler.List))

	// Workspace: List is any authenticated role (the picker source for
	// every VM/Database/Object Storage/Docker/Kubernetes create flow);
	// every other route is Admin-only.
	mux.Handle("GET /api/workspaces", authenticated(workspaceHandler.List))
	mux.Handle("POST /api/workspaces", requireAdmin(workspaceHandler.Create))
	mux.Handle("GET /api/workspaces/{id}", requireAdmin(workspaceHandler.Get))
	mux.Handle("PATCH /api/workspaces/{id}", requireAdmin(workspaceHandler.Update))
	// Permanent delete, distinct from PATCH's is_active deactivation --
	// requires exact-name confirmation and blocks when the workspace still
	// has any VM/database/object storage attached (see
	// WorkspaceService.Delete).
	mux.Handle("DELETE /api/workspaces/{id}", requireAdmin(workspaceHandler.Delete))
	mux.Handle("GET /api/workspaces/{workspaceId}/members", requireAdmin(workspaceHandler.ListMembers))
	mux.Handle("POST /api/workspaces/{workspaceId}/members", requireAdmin(workspaceHandler.AddMember))
	mux.Handle("DELETE /api/workspaces/{workspaceId}/members/{userId}", requireAdmin(workspaceHandler.RemoveMember))

	// Admin only: generic resources (DATABASE/OBJECT_STORAGE placeholders;
	// VM creation/update goes through /api/vms below, not here).
	mux.Handle("GET /api/resources", requireAdmin(resourceHandler.List))
	mux.Handle("GET /api/resources/{id}", requireAdmin(resourceHandler.Get))
	mux.Handle("POST /api/resources", requireAdmin(withinPlanResource(resourceHandler.Create)))
	mux.Handle("PATCH /api/resources/{id}", requireAdmin(resourceHandler.Update))

	// Admin only: VM create/update/access (GET is authenticated-any-role above).
	mux.Handle("POST /api/vms", requireAdmin(withinPlan(services.LimitVMs, vmHandler.Create)))
	mux.Handle("POST /api/vms/agent-only", requireAdmin(withinPlan(services.LimitVMs, vmAgentHandler.ConnectAgentOnly)))
	mux.Handle("PATCH /api/vms/{id}", requireAdmin(vmHandler.Update))
	// Step 22: removes the VM resource from Infra Hub Center only -- never
	// the actual remote server. Requires exact-name confirmation (see
	// VMService.Delete).
	mux.Handle("DELETE /api/vms/{id}", requireAdmin(vmHandler.Delete))
	mux.Handle("GET /api/vms/{id}/access", requireAdmin(vmHandler.ListAccess))

	// Admin only: named, reusable SSH key credentials (replaces the old
	// per-VM paste-once "credentials/ssh" endpoints -- a VM now points at
	// one of these via ssh_key_credential_id instead of storing its own key).
	mux.Handle("POST /api/ssh-key-credentials", requireAdmin(sshKeyCredentialHandler.Create))
	mux.Handle("GET /api/ssh-key-credentials", requireAdmin(sshKeyCredentialHandler.List))
	mux.Handle("GET /api/ssh-key-credentials/{id}", requireAdmin(sshKeyCredentialHandler.Get))
	mux.Handle("PATCH /api/ssh-key-credentials/{id}", requireAdmin(sshKeyCredentialHandler.Rename))
	mux.Handle("DELETE /api/ssh-key-credentials/{id}", requireAdmin(sshKeyCredentialHandler.Delete))

	// Admin only: connection testing, host-key trust, discovery (Step 5
	// §44). The two GET endpoints are any authenticated role, individually
	// checking VM authorization inside the handler (Step 5 §45-47).
	mux.Handle("POST /api/vms/{id}/connection-test", requireAdmin(sshHandler.TestConnection))
	mux.Handle("POST /api/vms/{id}/discover", requireAdmin(sshHandler.Discover))
	mux.Handle("POST /api/vms/{id}/host-key/trust", requireAdmin(sshHandler.TrustHostKey))
	mux.Handle("GET /api/vms/{id}/connection-status", authenticated(sshHandler.GetConnectionStatus))

	// Admin only: per-VM Docker agent install/status (Docker+Kubernetes
	// monitoring rework, Phase 1). Install is safe to call again -- see
	// DockerAgentHandler's doc comment.
	mux.Handle("POST /api/vms/{id}/docker-agent/install", requireAdmin(dockerAgentHandler.Install))
	mux.Handle("GET /api/vms/{id}/docker-agent/install-stream", requireAdmin(dockerAgentHandler.InstallStream))
	mux.Handle("POST /api/vms/{id}/docker-agent/manual", requireAdmin(dockerAgentHandler.ManualInstall))
	mux.Handle("GET /api/vms/{id}/docker-agent/status", requireAdmin(dockerAgentHandler.Status))
	mux.Handle("POST /api/vms/{id}/docker-agent/connection-test", requireAdmin(dockerAgentHandler.TestConnection))

	// Admin only: per-VM VM Agent manual-install/status (push-based
	// metrics/logs, additive alongside the existing SSH scheduler -- see
	// services/vm_agent_hub.go's doc comment). No SSH-based automated
	// install route exists (see services/vm_agent_install.go's doc
	// comment) -- ManualInstall is the only way to (re)issue a token +
	// docker run command. Metrics/logs reads are authenticated-any-role,
	// individually checking vm.view inside the handler, same as
	// packages/monitoring.
	mux.Handle("POST /api/vms/{id}/vm-agent/manual", requireAdmin(vmAgentHandler.ManualInstall))
	mux.Handle("GET /api/vms/{id}/vm-agent/status", requireAdmin(vmAgentHandler.Status))
	mux.Handle("POST /api/vms/{id}/vm-agent/connection-test", requireAdmin(vmAgentHandler.TestConnection))
	mux.Handle("GET /api/vms/{id}/vm-agent/metrics/current", authenticated(vmAgentMetricsHandler.Current))
	mux.Handle("GET /api/vms/{id}/vm-agent/metrics/history", authenticated(vmAgentMetricsHandler.History))
	mux.Handle("GET /api/vms/{id}/vm-agent/metrics/stream", authenticated(vmAgentMetricsHandler.Stream))
	mux.Handle("GET /api/vms/{id}/vm-agent/logs/recent", authenticated(vmAgentLogsHandler.RecentLogs))
	mux.Handle("GET /api/vms/{id}/vm-agent/logs/stream", authenticated(vmAgentLogsHandler.StreamLogs))
	// Step 22: browser-based VM console -- authenticated any role, its own
	// in-handler vm.connect check (not vm.view) is the real gate, mirroring
	// the WebSocket-authorization shape every other stream in this project
	// uses (see vm_console.go's package doc for why vm.connect, not
	// vm.view, is the right permission here).
	mux.Handle("GET /api/vms/{id}/console", authenticated(vmConsoleHandler.Console))
	mux.Handle("GET /api/vms/{id}/discovery", authenticated(sshHandler.GetDiscoveryHistory))

	// Step 6: monitoring. The two GET endpoints are any authenticated role
	// (individually checking VM authorization, spec §40); manual collection
	// is admin-only (spec §48/§49).
	mux.Handle("GET /api/vms/{id}/monitoring/current", authenticated(monitoringHandler.GetCurrent))
	mux.Handle("GET /api/vms/{id}/monitoring/history", authenticated(monitoringHandler.GetHistory))
	mux.Handle("POST /api/vms/{id}/monitoring/collect", requireAdmin(monitoringHandler.Collect))

	// Step 7: package inventory/updates. GETs are any authenticated role
	// (individually checking vm.view, spec §50); scan/refresh/acknowledge/
	// dismiss are admin-only (spec §29/§51).
	mux.Handle("GET /api/vms/{id}/packages", authenticated(packageHandler.List))
	mux.Handle("GET /api/vms/{id}/packages/updates", authenticated(packageHandler.ListUpdates))
	mux.Handle("GET /api/vms/{id}/packages/summary", authenticated(packageHandler.Summary))
	mux.Handle("GET /api/vms/{id}/packages/discovery-status", authenticated(packageHandler.DiscoveryStatus))
	mux.Handle("GET /api/vms/{id}/packages/{packageId}", authenticated(packageHandler.Get))
	mux.Handle("POST /api/vms/{id}/packages/scan", requireAdmin(packageHandler.Scan))
	mux.Handle("POST /api/vms/{id}/packages/refresh", requireAdmin(packageHandler.Refresh))
	mux.Handle("PUT /api/vms/{id}/packages/baseline", requireAdmin(packageHandler.ResetBaseline))
	mux.Handle("POST /api/vms/{id}/packages/{packageId}/acknowledge", requireAdmin(packageHandler.Acknowledge))
	mux.Handle("POST /api/vms/{id}/packages/{packageId}/dismiss", requireAdmin(packageHandler.Dismiss))
	mux.Handle("GET /api/vms/{id}/external-packages", authenticated(packageHandler.ListExternal))
	mux.Handle("POST /api/vms/{id}/external-packages/scan", requireAdmin(packageHandler.ScanExternal))

	// Step 7: cross-VM recommendations dashboard (spec §38) -- authenticated
	// any role, restricted to the caller's authorized VMs inside the handler.
	mux.Handle("GET /api/recommendations", authenticated(recommendationHandler.List))

	// Step 8: Docker discovery/inventory/metrics. GETs (REST and the
	// WebSocket stream alike) are any authenticated role, individually
	// checking vm.view plus, for every container-scoped endpoint, that the
	// container actually belongs to this VM (spec §63/§75); scan is
	// admin-only (spec §61).
	mux.Handle("GET /api/vms/{id}/docker", authenticated(dockerHandler.Overview))
	mux.Handle("GET /api/vms/{id}/docker/summary", authenticated(dockerHandler.Summary))
	mux.Handle("GET /api/vms/{id}/docker/containers", authenticated(dockerHandler.ListContainers))
	mux.Handle("GET /api/vms/{id}/docker/containers/{containerId}", authenticated(dockerHandler.GetContainer))
	mux.Handle("GET /api/vms/{id}/docker/images", authenticated(dockerHandler.ListImages))
	mux.Handle("GET /api/vms/{id}/docker/networks", authenticated(dockerHandler.ListNetworks))
	mux.Handle("GET /api/vms/{id}/docker/volumes", authenticated(dockerHandler.ListVolumes))
	mux.Handle("POST /api/vms/{id}/docker/scan", requireAdmin(dockerHandler.Scan))
	mux.Handle("GET /api/vms/{id}/docker/metrics/current", authenticated(dockerHandler.MetricsCurrent))
	mux.Handle("GET /api/vms/{id}/docker/containers/{containerId}/metrics/current", authenticated(dockerHandler.ContainerMetricsCurrent))
	mux.Handle("GET /api/vms/{id}/docker/containers/{containerId}/metrics/history", authenticated(dockerHandler.ContainerMetricsHistory))
	mux.Handle("GET /api/vms/{id}/docker/containers/{containerId}/stats/stream", authenticated(dockerHandler.Stream))

	// Step 24: the new top-level Docker Monitoring/Logs section. Overview
	// and the logs stream are authenticated-any-role (each individually
	// scopes its own result to the caller -- Admin unrestricted, Member to
	// their docker.monitor/docker.logs grants); access-grant management is
	// Admin-only, like every other grant/permission-management endpoint.
	mux.Handle("GET /api/docker/overview", authenticated(dockerHandler.MonitoringOverview))
	mux.Handle("GET /api/docker/containers/{containerId}/logs/stream", authenticated(dockerLogsHandler.Stream))
	mux.Handle("GET /api/docker/containers/{containerId}/logs/search", authenticated(dockerLogsHandler.Search))
	mux.Handle("PUT /api/docker/containers/{containerId}/name", requireAdmin(dockerHandler.SetContainerDisplayName))
	mux.Handle("GET /api/docker/my-access", authenticated(dockerAccessHandler.MyAccess))
	mux.Handle("GET /api/docker/access-grants", requireAdmin(dockerAccessHandler.ListAll))
	mux.Handle("POST /api/docker/access-grants", requireAdmin(dockerAccessHandler.Grant))
	mux.Handle("DELETE /api/docker/access-grants/{id}", requireAdmin(dockerAccessHandler.Revoke))

	// Step 25: standalone Kubernetes clusters. Cluster setup/credentials/
	// connection-test/scan are Admin-only, mirroring Object Storage's own
	// CRUD shape exactly. Overview and the pod-logs stream are
	// authenticated-any-role (each scopes its own result to the caller via
	// the same docker_access_grants table Step 24 introduced -- Admin
	// unrestricted, Member to their k8s.monitor/k8s.logs grants); grant
	// management itself reuses /api/docker/access-grants and
	// /api/docker/my-access above (a grant row's permission string alone
	// says whether it's a Docker or K8s grant, so no parallel endpoint is
	// needed).
	mux.Handle("GET /api/k8s/clusters", requireAdmin(k8sHandler.List))
	mux.Handle("POST /api/k8s/clusters", requireAdmin(withinPlan(services.LimitK8sClusters, k8sHandler.Configure)))
	mux.Handle("GET /api/k8s/clusters/{id}", requireAdmin(k8sHandler.Get))
	mux.Handle("PATCH /api/k8s/clusters/{id}", requireAdmin(k8sHandler.Update))
	mux.Handle("DELETE /api/k8s/clusters/{id}", requireAdmin(k8sHandler.Delete))
	mux.Handle("PUT /api/k8s/clusters/{id}/monitoring", requireAdmin(k8sHandler.SetMonitoringEnabled))
	mux.Handle("POST /api/k8s/clusters/{id}/agent-token", requireAdmin(k8sHandler.RegenerateAgentToken))
	mux.Handle("POST /api/k8s/clusters/{id}/connection-test", requireAdmin(k8sHandler.TestConnection))
	mux.Handle("POST /api/k8s/clusters/{id}/scan", requireAdmin(k8sHandler.Scan))
	mux.Handle("GET /api/k8s/clusters/{id}/nodes", requireAdmin(k8sHandler.ListNodes))
	mux.Handle("GET /api/k8s/clusters/{id}/resources", requireAdmin(k8sHandler.ResourceSummary))

	// Docker Hosts: standalone, agent-only Docker targets -- mirrors the
	// K8s cluster CRUD block above 1:1 (no connection-test/scan/nodes/
	// resources yet; see docker_host.go's doc comment on scope).
	mux.Handle("GET /api/docker/hosts", requireAdmin(dockerHostHandler.List))
	mux.Handle("POST /api/docker/hosts", requireAdmin(withinPlan(services.LimitDockerHosts, dockerHostHandler.Configure)))
	mux.Handle("GET /api/docker/hosts/{id}", requireAdmin(dockerHostHandler.Get))
	mux.Handle("DELETE /api/docker/hosts/{id}", requireAdmin(dockerHostHandler.Delete))
	mux.Handle("PUT /api/docker/hosts/{id}/monitoring", requireAdmin(dockerHostHandler.SetMonitoringEnabled))
	mux.Handle("POST /api/docker/hosts/{id}/agent-token", requireAdmin(dockerHostHandler.RegenerateAgentToken))
	mux.Handle("POST /api/docker/hosts/{id}/connection-test", requireAdmin(dockerHostHandler.TestConnection))
	// Live container/stats/logs surface for the top-level Docker
	// Monitoring/Logs dashboards -- any authenticated role, gated
	// internally by docker.monitor/docker.logs via CanAccessDockerFeature
	// (never requireAdmin, unlike every other Docker Host route above,
	// which is pure CRUD/agent-management, Admin-only end to end).
	mux.Handle("GET /api/docker/hosts/{id}/containers", authenticated(dockerHostHandler.ListContainers))
	mux.Handle("GET /api/docker/hosts/{id}/resources", authenticated(dockerHostHandler.HostResources))
	mux.Handle("GET /api/docker/hosts/{id}/system-metrics", authenticated(dockerHostHandler.SystemMetrics))
	mux.Handle("GET /api/docker/hosts/{id}/containers/{containerId}/logs/search", authenticated(dockerHostHandler.Search))
	mux.Handle("GET /api/docker/hosts/{id}/containers/{containerId}/logs/stream", authenticated(dockerHostHandler.StreamLogs))

	mux.Handle("GET /api/k8s/overview", authenticated(k8sOverviewHandler.MonitoringOverview))
	mux.Handle("GET /api/k8s/pods/{podId}/logs/stream", authenticated(k8sLogsHandler.Stream))
	mux.Handle("GET /api/k8s/pods/{podId}/logs/search", authenticated(k8sLogsHandler.Search))
	// The in-cluster agent's own inbound connection -- authenticated by its
	// bearer token (see K8sAgentHandler's doc comment), never the
	// session-cookie model above, so deliberately NOT wrapped in
	// authenticated/requireAdmin.
	mux.Handle("GET /api/k8s/agent/connect", http.HandlerFunc(k8sAgentHandler.Connect))
	mux.Handle("PUT /api/k8s/pods/{podId}/name", requireAdmin(k8sHandler.SetPodDisplayName))
	// The per-VM Docker agent's own inbound connection -- same
	// bearer-token authentication, deliberately NOT wrapped in
	// authenticated/requireAdmin (see DockerAgentHandler.Connect's doc
	// comment).
	mux.Handle("GET /api/docker-agent/connect", http.HandlerFunc(dockerAgentHandler.Connect))
	// The push-based VM Agent's own inbound connection -- same
	// bearer-token authentication, deliberately NOT wrapped in
	// authenticated/requireAdmin (see VMAgentHandler.Connect's doc comment).
	mux.Handle("GET /api/vm-agent/connect", http.HandlerFunc(vmAgentHandler.Connect))
	// TEMPORARY, capture-only: logs whatever DigitalOcean's Logsink
	// actually sends (path/headers/body) so the real database-logsink
	// ingest handler can be built against confirmed field names instead
	// of guessed ones -- see the "Real logs for DigitalOcean-managed
	// Postgres" plan's Part A. Remove once Part C's real handler exists.
	mux.HandleFunc("POST /api/_debug/logsink-capture", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		logger.Info("logsink capture", "method", r.Method, "path", r.URL.Path, "raw_query", r.URL.RawQuery,
			"headers", r.Header, "body", string(body))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":false,"items":[]}`))
	})

	// Monitoring/Logs Folder > Dashboard: the four independent trees
	// (Monitoring>Docker, Monitoring>Kubernetes, Logs>Docker,
	// Logs>Kubernetes), discriminated by `feature`. Folder CRUD and
	// Dashboard create/rename/move/resource-selection/widgets/delete are
	// Admin-only; List/Get are any authenticated role, scoped by
	// MonitoringDashboardService (Admin sees everything, a Member sees
	// only Dashboards whose bound VM/cluster they hold the matching
	// docker.monitor/docker.logs/k8s.monitor/k8s.logs grant on).
	mux.Handle("GET /api/monitoring-folders", requireAdmin(monitoringDashboardsHandler.ListFolders))
	mux.Handle("POST /api/monitoring-folders", requireAdmin(monitoringDashboardsHandler.CreateFolder))
	mux.Handle("GET /api/monitoring-folders/{id}", authenticated(monitoringDashboardsHandler.GetFolder))
	mux.Handle("PATCH /api/monitoring-folders/{id}", requireAdmin(monitoringDashboardsHandler.RenameFolder))
	mux.Handle("DELETE /api/monitoring-folders/{id}", requireAdmin(monitoringDashboardsHandler.DeleteFolder))
	mux.Handle("GET /api/monitoring-dashboards", authenticated(monitoringDashboardsHandler.List))
	mux.Handle("POST /api/monitoring-dashboards", requireAdmin(monitoringDashboardsHandler.Create))
	mux.Handle("GET /api/monitoring-dashboards/{id}", authenticated(monitoringDashboardsHandler.Get))
	mux.Handle("PATCH /api/monitoring-dashboards/{id}", requireAdmin(monitoringDashboardsHandler.Update))
	mux.Handle("PUT /api/monitoring-dashboards/{id}/resource-selection", requireAdmin(monitoringDashboardsHandler.SetResourceSelection))
	mux.Handle("PUT /api/monitoring-dashboards/{id}/widgets", requireAdmin(monitoringDashboardsHandler.SetWidgets))
	mux.Handle("DELETE /api/monitoring-dashboards/{id}", requireAdmin(monitoringDashboardsHandler.Delete))
	// The new Monitoring>Kubernetes Dashboard Overview's data source --
	// authenticated-any-role (k8s.monitor-scoped inside the handler),
	// unlike K8sHandler.ResourceSummary/ListNodes which stay Admin-only.
	mux.Handle("GET /api/k8s/overview/clusters/{clusterId}/resources", authenticated(k8sOverviewHandler.ClusterResources))

	// Per-user saved filters ("save in dashboard name") for the Docker/K8s
	// Monitoring/Logs dashboards -- authenticated-any-role, always scoped
	// to the caller's own saved views.
	mux.Handle("GET /api/saved-views", authenticated(savedViewsHandler.List))
	mux.Handle("POST /api/saved-views", authenticated(savedViewsHandler.Create))
	mux.Handle("DELETE /api/saved-views/{id}", authenticated(savedViewsHandler.Delete))
	mux.Handle("GET /api/saved-view-folders", authenticated(savedViewsHandler.FolderList))
	mux.Handle("POST /api/saved-view-folders", authenticated(savedViewsHandler.FolderCreate))
	mux.Handle("DELETE /api/saved-view-folders/{id}", authenticated(savedViewsHandler.FolderDelete))

	// Step 9: Update Center. Read-only OS/kernel/reboot/package-update
	// views are any authenticated role, individually scoped (spec §45/
	// §46 -- a member's global list is restricted to their authorized
	// VMs, never a global count); every update-plan endpoint (create,
	// view, validate, approve, cancel) is admin-only end to end (spec
	// §43's "Keep update planning Admin-only"), and update-plans/refresh/
	// precheck never execute an OS or package update -- see
	// docs/update-center.md.
	mux.Handle("GET /api/updates", authenticated(updatesHandler.List))
	mux.Handle("GET /api/vms/{id}/updates", authenticated(updatesHandler.GetVMUpdates))
	mux.Handle("GET /api/vms/{id}/updates/summary", authenticated(updatesHandler.GetVMUpdatesSummary))
	mux.Handle("GET /api/vms/{id}/updates/security", authenticated(updatesHandler.GetVMUpdatesSecurity))
	mux.Handle("GET /api/vms/{id}/updates/kernel", authenticated(updatesHandler.GetVMUpdatesKernel))
	mux.Handle("POST /api/vms/{id}/updates/precheck", requireAdmin(updatesHandler.RunPrecheck))
	mux.Handle("POST /api/vms/{id}/updates/refresh", requireAdmin(updatesHandler.RefreshUpdates))
	mux.Handle("POST /api/vms/{id}/update-plans", requireAdmin(updatesHandler.CreatePlan))
	mux.Handle("GET /api/vms/{id}/update-plans", requireAdmin(updatesHandler.ListPlansForVM))
	mux.Handle("GET /api/update-plans/{id}", requireAdmin(updatesHandler.GetPlan))
	mux.Handle("POST /api/update-plans/{id}/validate", requireAdmin(updatesHandler.ValidatePlan))
	mux.Handle("POST /api/update-plans/{id}/approve", requireAdmin(updatesHandler.ApprovePlan))
	mux.Handle("POST /api/update-plans/{id}/cancel", requireAdmin(updatesHandler.CancelPlan))

	// Step 10: the execution engine. POST .../execute is the only endpoint
	// in this entire project that can cause a real change on a VM --
	// admin-only, requires explicit {"confirmation": true}, never accepts
	// a raw command. Every other endpoint here is either admin-only
	// (cancel, verify) or any-authenticated-role with per-operation
	// vm.view authorization inside the handler (get/logs/results/history),
	// mirroring Step 8's Docker WebSocket authorization shape exactly.
	mux.Handle("POST /api/update-plans/{id}/execute", requireAdmin(updateOperationsHandler.Execute))
	mux.Handle("GET /api/update-operations", authenticated(updateOperationsHandler.List))
	mux.Handle("GET /api/vms/{id}/update-operations", authenticated(updateOperationsHandler.ListForVM))
	mux.Handle("GET /api/update-operations/{id}", authenticated(updateOperationsHandler.Get))
	mux.Handle("GET /api/update-operations/{id}/logs", authenticated(updateOperationsHandler.Logs))
	mux.Handle("GET /api/update-operations/{id}/logs/stream", authenticated(updateOperationsHandler.LogsStream))
	mux.Handle("GET /api/update-operations/{id}/steps", authenticated(updateOperationsHandler.Steps))
	mux.Handle("GET /api/update-operations/{id}/results", authenticated(updateOperationsHandler.Results))
	mux.Handle("POST /api/update-operations/{id}/cancel", requireAdmin(updateOperationsHandler.Cancel))
	mux.Handle("POST /api/update-operations/{id}/verify", requireAdmin(updateOperationsHandler.Verify))

	// Step 11: controlled VM reboot. POST .../reboot is the only other
	// endpoint in this project that can cause a real change on a VM --
	// admin-only, requires explicit {"confirmation": true}, never accepts
	// a raw command. The precheck endpoint is admin-only but read-only
	// (never sends a reboot command); every GET is any authenticated
	// role with per-operation vm.view authorization inside the handler.
	mux.Handle("POST /api/vms/{id}/reboot", requireAdmin(rebootOperationsHandler.Reboot))
	mux.Handle("POST /api/vms/{id}/reboot/precheck", requireAdmin(rebootOperationsHandler.Precheck))
	mux.Handle("GET /api/vms/{id}/reboot-operations", authenticated(rebootOperationsHandler.ListForVM))
	mux.Handle("GET /api/reboot-operations", authenticated(rebootOperationsHandler.List))
	mux.Handle("GET /api/reboot-operations/{id}", authenticated(rebootOperationsHandler.Get))
	mux.Handle("GET /api/reboot-operations/{id}/status", authenticated(rebootOperationsHandler.Get))
	mux.Handle("GET /api/reboot-operations/{id}/logs", authenticated(rebootOperationsHandler.Logs))
	mux.Handle("GET /api/reboot-operations/{id}/logs/stream", authenticated(rebootOperationsHandler.LogsStream))
	mux.Handle("GET /api/reboot-operations/{id}/results", authenticated(rebootOperationsHandler.Results))
	mux.Handle("POST /api/reboot-operations/{id}/cancel", requireAdmin(rebootOperationsHandler.Cancel))
	mux.Handle("POST /api/reboot-operations/{id}/verify", requireAdmin(rebootOperationsHandler.Verify))

	// Standalone database monitoring (spec: "Do NOT make VM -> Database the
	// required architecture" -- a database is a first-class resource under
	// a Workspace, connected directly via TCP/TLS, never a VM child).
	// Strictly read-only for metrics/performance -- no SQL
	// console, no arbitrary query execution, no database mutation anywhere
	// in this project. GETs (REST and the WebSocket stream alike) are any
	// authenticated role, individually checking database.view/
	// database.performance inside the handler (404-not-403 IDOR
	// discipline); configure/update/delete/test/access-grant are
	// admin-only.
	mux.Handle("GET /api/databases", authenticated(databaseHandler.List))
	mux.Handle("POST /api/databases", requireAdmin(withinPlan(services.LimitDatabases, databaseHandler.Configure)))
	mux.Handle("GET /api/databases/performance", authenticated(databaseHandler.GlobalPerformanceOverview))
	mux.Handle("GET /api/databases/{id}", authenticated(databaseHandler.Get))
	mux.Handle("GET /api/databases/{id}/monitoring-health", authenticated(databaseHandler.MonitoringHealth))
	mux.Handle("PATCH /api/databases/{id}", requireAdmin(databaseHandler.Update))
	mux.Handle("DELETE /api/databases/{id}", requireAdmin(databaseHandler.Delete))
	mux.Handle("POST /api/databases/{id}/test", requireAdmin(databaseHandler.Test))
	mux.Handle("POST /api/databases/{id}/access", requireAdmin(databaseHandler.GrantAccess))
	mux.Handle("DELETE /api/databases/{id}/access/{userId}", requireAdmin(databaseHandler.RevokeAccess))
	// Step 18 Phase 2: the "Authorized Members" list on the database detail
	// page -- mirrors GET /api/vms/{id}/access exactly, same admin-only
	// level as the Grant/Revoke routes just above.
	mux.Handle("GET /api/databases/{id}/access", requireAdmin(databaseHandler.ListAccess))
	mux.Handle("GET /api/databases/{id}/metrics/current", authenticated(databaseHandler.MetricsCurrent))
	mux.Handle("GET /api/databases/{id}/metrics/history", authenticated(databaseHandler.MetricsHistory))
	mux.Handle("GET /api/databases/{id}/metrics/stream", authenticated(databaseHandler.MetricsStream))

	// Advanced database performance monitoring -- deeper read access on
	// top of the fast metrics above (query text itself stays Admin/
	// database.query_details-gated inside the handler).
	mux.Handle("GET /api/databases/{id}/performance", authenticated(databaseHandler.Performance))
	mux.Handle("GET /api/databases/{id}/performance/history", authenticated(databaseHandler.PerformanceHistory))
	mux.Handle("GET /api/databases/{id}/performance/stream", authenticated(databaseHandler.PerformanceStream))
	mux.Handle("GET /api/databases/{id}/queries", authenticated(databaseHandler.Queries))
	mux.Handle("GET /api/databases/{id}/queries/{fingerprint}", authenticated(databaseHandler.QueryDetail))
	mux.Handle("GET /api/databases/{id}/connections", authenticated(databaseHandler.Connections))
	mux.Handle("GET /api/databases/{id}/locks", authenticated(databaseHandler.Locks))
	mux.Handle("GET /api/databases/{id}/replication", authenticated(databaseHandler.Replication))
	mux.Handle("GET /api/databases/{id}/storage", authenticated(databaseHandler.Storage))
	mux.Handle("GET /api/databases/{id}/storage/history", authenticated(databaseHandler.StorageHistory))

	// Database browser endpoints (Step 13, spec #101-107)
	// Read-only, safe access to database structure and data
	mux.Handle("GET /api/databases/{databaseId}/catalog", authenticated(databaseBrowserHandler.GetCatalog))
	mux.Handle("GET /api/databases/{databaseId}/schemas", authenticated(databaseBrowserHandler.GetSchemas))
	mux.Handle("GET /api/databases/{databaseId}/tables", authenticated(databaseBrowserHandler.GetTables))
	mux.Handle("GET /api/databases/{databaseId}/tables/{tableId}/columns", authenticated(databaseBrowserHandler.GetColumns))
	mux.Handle("GET /api/databases/{databaseId}/tables/{tableId}/rows", authenticated(databaseBrowserHandler.GetTableRows))
	mux.Handle("GET /api/databases/{databaseId}/tables/{tableId}/search", authenticated(databaseBrowserHandler.SearchTable))
	mux.Handle("GET /api/databases/{databaseId}/tables/{tableId}/indexes", authenticated(databaseBrowserHandler.GetIndexes))
	mux.Handle("GET /api/databases/{databaseId}/logs", authenticated(databaseBrowserHandler.GetLogs))

	// Step 14: controlled database operations + admin remediation.
	// Recommendation -> Review -> Operation Plan -> Confirmation ->
	// Execute -> Live Output -> Result -> Audit. Every endpoint here is
	// Admin-only end to end (spec: "Members: NO database remediation
	// access by default" -- unlike every other database endpoint, there
	// is no grantable permission path around this, so requireAdmin at the
	// router level plus the handler's own internal check is intentional
	// defense-in-depth, not redundancy). POST .../confirm is the only
	// endpoint that can actually cause a real change on a database.
	mux.Handle("GET /api/database-operations", requireAdmin(databaseOperationsHandler.ListGlobal))
	mux.Handle("GET /api/databases/{id}/operations", requireAdmin(databaseOperationsHandler.ListForDatabase))
	mux.Handle("GET /api/databases/{id}/operations/capabilities", requireAdmin(databaseOperationsHandler.Capabilities))
	mux.Handle("POST /api/databases/{id}/operations/preview", requireAdmin(databaseOperationsHandler.Preview))
	mux.Handle("POST /api/databases/{id}/operations", requireAdmin(databaseOperationsHandler.Create))
	mux.Handle("GET /api/databases/{id}/operations/{operationId}", requireAdmin(databaseOperationsHandler.Get))
	mux.Handle("POST /api/databases/{id}/operations/{operationId}/confirm", requireAdmin(databaseOperationsHandler.Confirm))
	mux.Handle("POST /api/databases/{id}/operations/{operationId}/cancel", requireAdmin(databaseOperationsHandler.Cancel))
	mux.Handle("POST /api/databases/{id}/operations/{operationId}/retry", requireAdmin(databaseOperationsHandler.Retry))
	mux.Handle("DELETE /api/databases/{id}/operations/{operationId}", requireAdmin(databaseOperationsHandler.Delete))
	mux.Handle("GET /api/databases/{id}/operations/{operationId}/logs", requireAdmin(databaseOperationsHandler.Logs))
	mux.Handle("GET /api/databases/{id}/operations/{operationId}/logs/stream", requireAdmin(databaseOperationsHandler.LogsStream))

	// Step 16: central infrastructure alerts + notifications.
	// Recommendation -> Review -> Alert Rule -> Alert -> Notification ->
	// Admin/authorized user. Every GET is any authenticated role,
	// individually scoped to the caller's authorized resources exactly
	// like recommendations (spec §22); acknowledge/suppress and every
	// alert-rule/notification-policy mutation are Admin-only. Nothing
	// here ever executes remediation -- see Step 14's database
	// operations for this project's only operation-execution path.
	mux.Handle("GET /api/alerts", authenticated(alertsHandler.List))
	mux.Handle("GET /api/alerts/summary", authenticated(alertsHandler.Summary))
	mux.Handle("GET /api/alerts/stream", authenticated(alertsHandler.Stream))
	mux.Handle("GET /api/alerts/{id}", authenticated(alertsHandler.Get))
	mux.Handle("GET /api/alerts/{id}/history", authenticated(alertsHandler.History))
	mux.Handle("POST /api/alerts/{id}/acknowledge", requireAdmin(alertsHandler.Acknowledge))
	mux.Handle("POST /api/alerts/{id}/suppress", requireAdmin(alertsHandler.Suppress))

	mux.Handle("GET /api/alert-rules", requireAdmin(alertRulesHandler.ListGlobal))
	mux.Handle("GET /api/alert-rules/templates", requireAdmin(alertRulesHandler.Templates))
	mux.Handle("POST /api/alert-rules", requireAdmin(alertRulesHandler.Create))
	mux.Handle("GET /api/alert-rules/{id}", requireAdmin(alertRulesHandler.Get))
	mux.Handle("PUT /api/alert-rules/{id}", requireAdmin(alertRulesHandler.Update))
	mux.Handle("DELETE /api/alert-rules/{id}", requireAdmin(alertRulesHandler.Delete))
	mux.Handle("GET /api/resources/{resourceId}/alert-rules", requireAdmin(alertRulesHandler.ListForResource))

	mux.Handle("GET /api/notifications", authenticated(notificationsHandler.List))
	mux.Handle("POST /api/notifications/{id}/read", authenticated(notificationsHandler.MarkRead))
	mux.Handle("POST /api/notifications/read-all", authenticated(notificationsHandler.MarkAllRead))

	mux.Handle("GET /api/notification-policies", requireAdmin(notificationPoliciesHandler.List))
	mux.Handle("POST /api/notification-policies", requireAdmin(notificationPoliciesHandler.Create))
	mux.Handle("PUT /api/notification-policies/{id}", requireAdmin(notificationPoliciesHandler.Update))
	mux.Handle("DELETE /api/notification-policies/{id}", requireAdmin(notificationPoliciesHandler.Delete))
	mux.Handle("POST /api/notification-policies/{id}/test", requireAdmin(notificationPoliciesHandler.SendTest))

	// Standalone object storage monitoring (Step 17, Phase 1: schema +
	// adapter + CRUD + test-connection only -- no metrics/browser routes
	// yet, no write/delete/upload S3 API surface anywhere). Same
	// authorization shape as standalone databases: GET is any
	// authenticated role, individually checking object_storage.view inside
	// the handler (404-not-403 IDOR discipline); configure/update/delete/
	// test-connection/access-grant are admin-only.
	mux.Handle("GET /api/object-storage", authenticated(objectStorageHandler.List))
	mux.Handle("POST /api/object-storage", requireAdmin(withinPlan(services.LimitObjectStorage, objectStorageHandler.Configure)))
	// Step 17 Phase 5: cross-storage summary (dashboard/list-page stat
	// cards) -- registered here, textually before GET /api/object-storage/{id},
	// though Go 1.22+ net/http.ServeMux resolves this unambiguously by
	// specificity regardless of registration order (a literal path segment
	// always wins over a same-position {wildcard}), verified directly by
	// TestObjectStorageSummary_DoesNotCollideWithIDRoute hitting both this
	// path and a real /{id} in the same test.
	mux.Handle("GET /api/object-storage/summary", authenticated(objectStorageHandler.Summary))
	mux.Handle("GET /api/object-storage/{id}", authenticated(objectStorageHandler.Get))
	mux.Handle("PATCH /api/object-storage/{id}", requireAdmin(objectStorageHandler.Update))
	mux.Handle("DELETE /api/object-storage/{id}", requireAdmin(objectStorageHandler.Delete))
	mux.Handle("POST /api/object-storage/{id}/test-connection", requireAdmin(objectStorageHandler.TestConnection))
	mux.Handle("POST /api/object-storage/{id}/access", requireAdmin(objectStorageHandler.GrantAccess))
	mux.Handle("DELETE /api/object-storage/{id}/access/{userId}", requireAdmin(objectStorageHandler.RevokeAccess))
	// Step 18 Phase 2: the "Authorized Members" list on the object storage
	// detail page -- mirrors GET /api/vms/{id}/access exactly, same
	// admin-only level as the Grant/Revoke routes just above.
	mux.Handle("GET /api/object-storage/{id}/access", requireAdmin(objectStorageHandler.ListAccess))
	// Step 17 Phase 2: fast metrics -- authorizeObjectStorage itself
	// enforces object_storage.monitor (404-not-403), so these are exposed
	// to any authenticated caller here, same "authenticated" + in-handler
	// permission gate pattern as the Database metrics routes above.
	mux.Handle("GET /api/object-storage/{id}/metrics/current", authenticated(objectStorageHandler.MetricsCurrent))
	mux.Handle("GET /api/object-storage/{id}/metrics/history", authenticated(objectStorageHandler.MetricsHistory))
	// Step 17 Phase 3: read-only security/growth/health informational
	// endpoints -- object_storage.view (not .monitor), same in-handler
	// 404-not-403 IDOR discipline.
	mux.Handle("GET /api/object-storage/{id}/security", authenticated(objectStorageHandler.Security))
	mux.Handle("GET /api/object-storage/{id}/growth", authenticated(objectStorageHandler.Growth))
	mux.Handle("GET /api/object-storage/{id}/health", authenticated(objectStorageHandler.Health))
	// Step 17 Phase 4: read-only object browser -- authorizeObjectStorage
	// itself enforces object_storage.browser (List/Search/Metadata/Preview)
	// or object_storage.download (RequestDownload) per-endpoint,
	// 404-not-403 IDOR discipline. No write/delete/upload S3 route exists
	// anywhere. RequestDownload is POST (not GET), per the plan's explicit
	// routing decision -- see object_storage_browser.go's package doc
	// comment for the full reasoning and the resulting frontend-contract
	// divergence this needs to be reconciled against.
	mux.Handle("GET /api/object-storage/{id}/objects", authenticated(objectStorageBrowserHandler.ListObjects))
	mux.Handle("GET /api/object-storage/{id}/objects/prefix-size", authenticated(objectStorageBrowserHandler.PrefixSize))
	mux.Handle("GET /api/object-storage/{id}/objects/search", authenticated(objectStorageBrowserHandler.Search))
	mux.Handle("GET /api/object-storage/{id}/objects/metadata", authenticated(objectStorageBrowserHandler.GetObjectMetadata))
	mux.Handle("GET /api/object-storage/{id}/objects/preview", authenticated(objectStorageBrowserHandler.GetPreview))
	mux.Handle("POST /api/object-storage/{id}/objects/download", authenticated(objectStorageBrowserHandler.RequestDownload))

	// Step 21: unified Operations list -- authenticated any role, exactly
	// like /api/alerts and /api/my-access; the response scoping inside
	// OperationsHandler.loadUnifiedOperations (VM-access-restricted for
	// Members, database operations never included for a Member at all) is
	// the security boundary, not a route-level role gate. Read-only: every
	// mutating action stays on that operation's own existing route
	// (POST .../confirm, .../cancel, .../retry, .../execute, .../reboot
	// above), never duplicated here.
	mux.Handle("GET /api/operations", authenticated(operationsHandler.List))
	mux.Handle("GET /api/operations/summary", authenticated(operationsHandler.Summary))

	// Step 21: Audit Logs. Admin-only -- audit.view exists in the
	// permission catalog but is not resource-scoped and has no existing
	// grant path (see internal/handlers/audit_logs.go's package doc), so
	// this is a plain role gate, the same pattern as /api/permissions and
	// /api/notification-policies.
	mux.Handle("GET /api/audit-logs", requireAdmin(auditLogsHandler.List))
	mux.Handle("GET /api/audit-logs/summary", requireAdmin(auditLogsHandler.Summary))

	// Step 21: Settings. Personal settings are self-service, any
	// authenticated role, always scoped to the caller (never a path
	// parameter -- see me_settings.go's package doc). Platform settings
	// are Admin-only and read-only (see platform_settings.go's package doc
	// for why there is no PUT).
	mux.Handle("GET /api/me/settings", authenticated(meSettingsHandler.Get))
	mux.Handle("PUT /api/me/settings", authenticated(meSettingsHandler.Update))
	mux.Handle("PUT /api/me/password", authenticated(meSettingsHandler.ChangePassword))
	mux.Handle("GET /api/settings/platform", requireAdmin(platformSettingsHandler.Get))
	// Sign-in Methods: an Admin still sees the read-only booleans above,
	// but only an Owner can view/edit/test the actual configuration --
	// see platform_settings.go's package doc.
	mux.Handle("GET /api/settings/signin-methods", requireOwner(platformSettingsHandler.GetSignInMethods))
	mux.Handle("PUT /api/settings/github", requireOwner(platformSettingsHandler.UpdateGitHub))
	mux.Handle("PUT /api/settings/google", requireOwner(platformSettingsHandler.UpdateGoogle))
	mux.Handle("PUT /api/settings/smtp", requireOwner(platformSettingsHandler.UpdateSMTP))
	mux.Handle("POST /api/settings/smtp/test", requireOwner(platformSettingsHandler.TestSMTP))
	mux.Handle("POST /api/settings/oauth/{provider}/test", requireOwner(platformSettingsHandler.TestOAuth))

	var h http.Handler = mux
	h = middleware.Recovery(logger)(h)
	h = middleware.RequireProxyKey(deps.ProxyKey)(h)
	h = middleware.CORS(deps.FrontendOrigin)(h)
	h = middleware.MaxBody(deps.MaxRequestBodyBytes)(h)
	h = middleware.SecurityHeaders(deps.CookieSecure)(h)
	h = middleware.Logging(logger)(h)

	return h
}
