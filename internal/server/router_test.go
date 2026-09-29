// Package server_test exercises the full HTTP stack -- real router, real
// middleware, real Postgres -- against the authentication and
// authorization behaviors required by the Step 3 spec. Every test skips
// (not fails) when DATABASE_URL is unset, matching the rest of this
// project's integration tests.
package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"vmcontrolcenter/backend/internal/database"
	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/handlers"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/server"
	"vmcontrolcenter/backend/internal/services"
)

// Shared across setup() and TestRequireAuthentication_ExpiredToken, which
// mints its own already-expired token with a separate short-lived
// TokenService using the same secret.
const testJWTSecret = "test-jwt-secret-not-for-production"

type testEnv struct {
	baseURL                  string
	pool                     *pgxpool.Pool
	store                    *repository.Store
	audit                    *services.AuditService
	authz                    *services.AuthorizationService
	auth                     *services.AuthService
	tokens                   *services.TokenService
	workspaces               *services.WorkspaceService
	resources                *services.ResourceService
	vms                      *services.VMService
	access                   *services.AccessService
	sshKeyCredentials        *services.SSHKeyCredentialService
	hostKeys                 *services.HostKeyService
	ssh                      *services.SSHService
	discovery                *services.VMDiscoveryService
	monitoring               *services.VMMonitoringService
	scheduler                *services.MonitoringScheduler
	packages                 *services.PackageService
	packageScheduler         *services.PackageScanScheduler
	docker                   *services.DockerDiscoveryService
	dockerScheduler          *services.DockerDiscoveryScheduler
	dockerCache              *services.DockerMetricsCache
	dockerAccess             *services.DockerAccessService
	k8sClusters              *services.K8sClusterService
	k8sAgentHub              *services.K8sAgentHub
	k8sAgentTokens           *services.K8sAgentTokenService
	k8s                      *services.K8sService
	k8sDiscovery             *services.K8sDiscoveryService
	k8sScheduler             *services.K8sDiscoveryScheduler
	dockerAgentHub           *services.DockerAgentHub
	dockerAgentTokens        *services.DockerAgentTokenService
	dockerAgent              *services.DockerAgentService
	dockerAgentInstall       *services.DockerAgentInstallService
	vmAgentHub               *services.VMAgentHub
	vmAgentTokens            *services.VMAgentTokenService
	vmAgent                  *services.VMAgentService
	vmAgentInstall           *services.VMAgentInstallService
	dockerLogCapture         *services.DockerLogCaptureService
	dockerLogRetentionSvc    *services.DockerLogRetentionService
	k8sLogCapture            *services.K8sLogCaptureService
	k8sLogRetentionSvc       *services.K8sLogRetentionService
	osUpdates                *services.OSUpdateService
	updatePlans              *services.UpdatePlanService
	updateExecution          *services.UpdateExecutionService
	updateWorker             *services.UpdateExecutionWorker
	rebootExecution          *services.RebootExecutionService
	rebootWorker             *services.RebootExecutionWorker
	databases                *services.DatabaseService
	databaseCredentials      *services.StandaloneDatabaseCredentialService
	databaseMetrics          *services.DatabaseMetricsService
	databaseCache            *services.DatabaseMetricsCache
	databaseDeepMetrics      *services.DatabaseDeepMetricsService
	databaseDeepCache        *services.DatabaseDeepMetricsCache
	databaseOperations       *services.DatabaseOperationService
	alertEngine              *services.AlertEngine
	alertRules               *services.AlertRuleService
	notificationPolicies     *services.NotificationPolicyService
	objectStorages           *services.ObjectStorageService
	objectStorageCredentials *services.StandaloneObjectStorageCredentialService
	objectStorageMetrics     *services.ObjectStorageMetricsService
	objectStorageCache       *services.ObjectStorageMetricsCache
	objectStorageDeepMetrics *services.ObjectStorageDeepMetricsService
	objectStorageDeepCache   *services.ObjectStorageDeepMetricsCache
	objectStorageBrowser     *services.ObjectStorageBrowserService
	userPreferences          *services.UserPreferencesService
}

func setup(t *testing.T) *testEnv {
	t.Helper()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL not set; skipping server integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := database.NewPool(ctx, databaseURL, database.PoolConfig{
		MaxConns: 5, MinConns: 1, ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("connect to database: %v", err)
	}
	t.Cleanup(pool.Close)

	store := repository.New(pool)
	// A realistic TTL, not a short one: this TokenService backs every test
	// in this file except TestRequireAuthentication_ExpiredToken (which
	// mints its own pre-expired token directly). A short shared TTL here
	// would make every other test flaky against real request latency.
	tokens := services.NewTokenService(testJWTSecret, 15*time.Minute)
	auth := services.NewAuthService(store, tokens, 7*24*time.Hour)
	authz := services.NewAuthorizationService(store.Queries)
	audit := services.NewAuditService(store)
	workspaceSvc := services.NewWorkspaceService(store)
	resourceSvc := services.NewResourceService(store)
	vmSvc := services.NewVMService(store, authz)
	accessSvc := services.NewAccessService(store)

	// A fresh key per test process is fine -- these tests only need
	// encrypt/decrypt to round-trip, never a stable key across runs.
	encryptionKey, err := services.GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("generate test encryption key: %v", err)
	}
	encryption, err := services.NewEncryptionService(encryptionKey)
	if err != nil {
		t.Fatalf("build test encryption service: %v", err)
	}
	// Short timeouts so the unreachable-host/timeout test cases in
	// ssh_test.go don't make the suite slow.
	connectTimeout := 2 * time.Second
	commandTimeout := 2 * time.Second
	sshKeyCredentialSvc := services.NewSSHKeyCredentialService(store, encryption)
	hostKeySvc := services.NewHostKeyService(store)
	sshSvc := services.NewSSHService(store, sshKeyCredentialSvc, hostKeySvc, connectTimeout)
	executor := services.NewRemoteExecutor()
	discoverySvc := services.NewVMDiscoveryService(store, sshSvc, executor, commandTimeout)

	// Same defaults the server itself uses (internal/config), just
	// constructed directly since tests don't go through config.Load().
	thresholds := services.HealthThresholds{
		CPUWarning: 80, CPUCritical: 90,
		MemoryWarning: 80, MemoryCritical: 90,
		DiskWarning: 80, DiskCritical: 90,
	}
	monitoringSvc := services.NewVMMonitoringService(store, sshSvc, executor, commandTimeout, thresholds)
	// Never .Run() here: that would start a real ticking background loop
	// per test. Tests call scheduler.CollectNow directly (via the HTTP
	// handler), which needs no running dispatcher/worker pool.
	scheduler := services.NewMonitoringScheduler(store, monitoringSvc, time.Minute, 5, nil)

	packageDetector := services.NewPackageManagerDetector(executor, commandTimeout)
	packageFactory := services.NewPackageManagerFactory(executor, commandTimeout)
	packageSvc := services.NewPackageService(store, sshSvc, packageDetector, packageFactory, commandTimeout)
	// Never .Run() here either, for the same reason as the monitoring
	// scheduler above -- tests call ScanNow/RefreshNow directly.
	packageScheduler := services.NewPackageScanScheduler(store, packageSvc, time.Hour, 2, nil)
	externalPackageSvc := services.NewExternalPackageScanner(store, sshSvc, executor, commandTimeout)

	dockerClient := services.NewDockerClient(executor, commandTimeout)
	dockerSvc := services.NewDockerDiscoveryService(store, sshSvc, dockerClient)
	// Never .Run() here either -- tests that need a scan call ScanNow
	// directly, and the IDOR/authorization tests write container fixture
	// rows straight into the database rather than scanning a real VM.
	dockerScheduler := services.NewDockerDiscoveryScheduler(store, dockerSvc, time.Hour, 2, nil)
	dockerCache := services.NewDockerMetricsCache()
	dockerAccessSvc := services.NewDockerAccessService(store, workspaceSvc)
	monitoringFolderSvc := services.NewMonitoringFolderService(store)
	monitoringDashboardSvc := services.NewMonitoringDashboardService(store, authz)

	// Step 25: standalone Kubernetes clusters, connected via an in-cluster
	// agent (never kubeconfig -- see services/k8s_credential.go) -- same
	// never-.Run()-a-scheduler-in-tests convention as every other feature
	// above; tests that need pod discovery call k8sDiscoverySvc.Discover
	// directly, driving a real fake agent WebSocket client (see
	// startFakeK8sAgent in k8s_test.go) through k8sAgentHub exactly like
	// production traffic would.
	k8sAgentHubSvc := services.NewK8sAgentHub()
	k8sAgentTokenSvc := services.NewK8sAgentTokenService(store)
	k8sClusterSvc := services.NewK8sClusterService(store, k8sAgentTokenSvc)
	k8sSvc := services.NewK8sService(store, k8sAgentHubSvc, connectTimeout)
	k8sDiscoverySvc := services.NewK8sDiscoveryService(store, k8sSvc)
	k8sScheduler := services.NewK8sDiscoveryScheduler(store, k8sDiscoverySvc, time.Hour, 2, nil)

	// Per-VM Docker agent (Docker+Kubernetes monitoring rework, Phase 1) --
	// same never-.Run()-a-scheduler-in-tests convention; tests that need a
	// connected agent drive one through dockerAgentHubSvc exactly like
	// startFakeK8sAgent does for the K8s agent (see docker_agent_test.go).
	// dockerAgentInstallSvc is wired for completeness but never exercised
	// end-to-end in tests -- it requires a real SSH-reachable VM.
	dockerAgentHubSvc := services.NewDockerAgentHub()
	dockerAgentTokenSvc := services.NewDockerAgentTokenService(store)
	dockerAgentSvc := services.NewDockerAgentService(store, dockerAgentHubSvc, connectTimeout)
	dockerAgentInstallSvc := services.NewDockerAgentInstallService(
		store, sshSvc, executor, dockerAgentTokenSvc, dockerAgentHubSvc, dockerAgentSvc, "wss://test.invalid/api/docker-agent/connect", 5*time.Second,
	)
	// Docker Hosts (standalone resource, no VM/SSH required) -- Connect
	// (above) falls back to this service's own token lookup whenever a
	// bearer token isn't a VM agent token, so it must be a real, wired
	// instance here too, not nil, or that fallback path nil-pointer-panics.
	dockerHostAgentTokenSvc := services.NewDockerHostAgentTokenService(store)
	dockerHostSvc := services.NewDockerHostService(store, dockerHostAgentTokenSvc)

	// VM Agent (push-based, additive alongside the SSH scheduler above) --
	// same never-.Run()-a-scheduler-in-tests convention; tests that need a
	// connected agent drive one through vmAgentHubSvc, mirroring
	// dockerAgentHubSvc's role above. vmAgentInstallSvc has no SSH
	// dependency at all (see services/vm_agent_install.go's doc comment)
	// -- it's just the backend-URL/run-command builder shared by
	// ConnectAgentOnly/ManualInstall.
	vmAgentTokenSvc := services.NewVMAgentTokenService(store)
	vmAgentSvc := services.NewVMAgentService(store, connectTimeout)
	vmAgentHubSvc := services.NewVMAgentHub(nil, vmAgentSvc.HandleMetricsPush)
	vmAgentSvc.SetHub(vmAgentHubSvc)
	vmAgentInstallSvc := services.NewVMAgentInstallService("wss://test.invalid/api/vm-agent/connect")

	// Log history: same never-.Run()-a-scheduler-in-tests convention --
	// tests that need captured log lines call dockerLogCaptureSvc.CaptureOne/
	// k8sLogCaptureSvc.CaptureOne directly, and retention tests call
	// .Cleanup directly.
	logRetention := 7 * 24 * time.Hour
	noopArchiver, err := services.NewLogArchiver(services.LogArchiveConfig{Backend: "none"})
	if err != nil {
		t.Fatalf("build noop log archiver: %v", err)
	}
	dockerLogCaptureSvc := services.NewDockerLogCaptureService(store, sshSvc, executor, commandTimeout, logRetention, dockerAgentSvc)
	dockerLogRetentionSvc := services.NewDockerLogRetentionService(store, 7, noopArchiver, nil)
	k8sLogCaptureSvc := services.NewK8sLogCaptureService(store, k8sSvc, logRetention)
	k8sLogRetentionSvc := services.NewK8sLogRetentionService(store, 7, noopArchiver, nil)

	// Step 9: no scheduler hook here (SetOSUpdateService is never called in
	// tests) -- tests that need OS-update data write os_updates rows or
	// call osUpdateSvc.Scan directly, mirroring the docker/package pattern
	// above of never starting a real ticking background loop in tests.
	osUpdateSvc := services.NewOSUpdateService(store, sshSvc, executor, commandTimeout)
	updatePlanSvc := services.NewUpdatePlanService(store, sshSvc, time.Hour)

	// Step 10: constructed like every other test service above, but never
	// .Run() -- tests that need to observe a completed execution call
	// updateExecutionSvc.Run(ctx, operationID) directly (synchronously, on
	// the test goroutine) rather than going through the worker's async
	// dispatch, mirroring ScanNow's direct-call pattern used everywhere
	// else in this file.
	updateExecutionSvc := services.NewUpdateExecutionService(
		store, sshSvc, executor, updatePlanSvc, discoverySvc, monitoringSvc, packageSvc, dockerSvc, osUpdateSvc, audit,
		commandTimeout, commandTimeout, 2*1024*1024, 100,
	)
	updateWorker := services.NewUpdateExecutionWorker(updateExecutionSvc, 2, 2, nil)

	// Step 11: same never-.Run()/call-Run()-directly convention as Step 10
	// above.
	rebootExecutionSvc := services.NewRebootExecutionService(
		store, sshSvc, executor, discoverySvc, monitoringSvc, packageSvc, dockerSvc, osUpdateSvc, audit,
		commandTimeout, commandTimeout, time.Millisecond, 2, 2*1024*1024,
	)
	rebootWorker := services.NewRebootExecutionWorker(rebootExecutionSvc, 2, 2, nil)

	// Standalone database monitoring: same never-.Run()/call-service-methods-
	// directly convention as every other feature above -- tests that need
	// metrics call databaseMetrics.CollectOne / databaseDeepMetrics.CollectDeep
	// directly.
	databaseCredentialSvc := services.NewStandaloneDatabaseCredentialService(store, encryption)
	databaseSvc := services.NewDatabaseService(store, databaseCredentialSvc)
	databaseThresholds := services.DatabaseHealthThresholds{ConnectionWarning: 80, ConnectionCritical: 95, MemoryWarning: 80, MemoryCritical: 95}
	databaseCache := services.NewDatabaseMetricsCache()
	databaseMetricsSvc := services.NewDatabaseMetricsService(store, databaseCredentialSvc, databaseCache, connectTimeout, commandTimeout, databaseThresholds)

	databasePerfThresholds := services.DatabasePerformanceThresholds{
		CacheHitWarning: 95, CacheHitCritical: 90, LockWarningCount: 3, SlowQueryMs: 1000, GrowthWarningPercent: 20,
	}
	databaseDeepCache := services.NewDatabaseDeepMetricsCache()
	databaseDeepMetricsSvc := services.NewDatabaseDeepMetricsService(
		store, databaseCredentialSvc, databaseDeepCache, connectTimeout, commandTimeout, databasePerfThresholds, false, 4096,
	)
	databaseMetricsScheduler := services.NewDatabaseMetricsScheduler(store, databaseMetricsSvc, time.Hour, 2, nil)
	databaseDeepMetricsScheduler := services.NewDatabaseDeepMetricsScheduler(store, databaseDeepMetricsSvc, time.Hour, 2, nil)
	databaseConnectionLimiter := services.NewDatabaseConnectionLimiter(3)
	databaseBrowserSvc := services.NewDatabaseBrowserService(store, databaseCredentialSvc, databaseConnectionLimiter)

	// Step 14: same never-.Run()/call-service-methods-directly convention
	// as every other feature above -- tests that need a worker call
	// databaseOperationSvc.Run directly.
	databaseOperationSvc := services.NewDatabaseOperationService(
		store, databaseCredentialSvc, audit, connectTimeout, commandTimeout, 5*time.Second, databaseThresholds, 1024*1024,
	)
	databaseOperationWorker := services.NewDatabaseOperationWorker(databaseOperationSvc, 2, 2, nil)

	// Step 16: same never-.Run()-the-scheduler-in-tests convention --
	// tests that need evaluation call alertEngine.EvaluateOnce directly.
	alertRuleSvc := services.NewAlertRuleService(store)
	alertSvc := services.NewAlertService(store, audit)
	notificationPolicySvc := services.NewNotificationPolicyService(store)
	if err := notificationPolicySvc.EnsureDefaultPolicy(context.Background()); err != nil {
		t.Fatalf("ensure default notification policy: %v", err)
	}
	notificationSvc := services.NewNotificationService(store, audit, 15*time.Minute, 5*time.Second, 1, services.EmailConfig{Timeout: 5 * time.Second}, nil)
	alertEngine := services.NewAlertEngine(store, audit, notificationSvc, nil, nil, nil)

	// Step 17: same never-.Run()-a-scheduler-in-tests convention as every
	// other feature above -- tests that need a fast-metrics sample call
	// objectStorageMetricsSvc.CollectOne directly (or write an
	// object_storage_metrics row straight into the database), mirroring
	// the database metrics test-setup pattern exactly.
	objectStorageCredentialSvc := services.NewStandaloneObjectStorageCredentialService(store, encryption)
	objectStorageSvc := services.NewObjectStorageService(store, objectStorageCredentialSvc)
	objectStorageCache := services.NewObjectStorageMetricsCache()
	objectStorageMetricsSvc := services.NewObjectStorageMetricsService(store, objectStorageCredentialSvc, objectStorageCache, connectTimeout)

	// Step 17 Phase 3: same never-.Run()-a-scheduler-in-tests convention --
	// tests that need a deep-metrics sample call
	// objectStorageDeepMetricsSvc.CollectDeep directly.
	objectStorageDeepCache := services.NewObjectStorageDeepMetricsCache()
	objectStorageDeepMetricsSvc := services.NewObjectStorageDeepMetricsService(
		store, objectStorageCredentialSvc, objectStorageCache, objectStorageDeepCache, connectTimeout, 20, 5, "CRITICAL",
	)

	// Step 17 Phase 4: object browser -- no scheduler, every call is
	// directly, synchronously driven by an inbound HTTP request in tests
	// exactly like in the real server.
	objectStorageBrowserSvc := services.NewObjectStorageBrowserService(store, objectStorageCredentialSvc)

	// Step 21: Operations/Audit Logs/Settings -- pure read/aggregation
	// services, no scheduler, nothing to avoid .Run()-ing here.
	auditQuerySvc := services.NewAuditQueryService(store)
	userPreferencesSvc := services.NewUserPreferencesService(store)
	// Empty env defaults -- SMTP/OAuth are deliberately unconfigured in
	// tests, exactly like the real app's default; PlatformSettingsService.Get
	// falls back to these when the DB row hasn't been given a value, so
	// tests exercising user creation never attempt a real send.
	platformSettingsSvc := services.NewPlatformSettingsService(store, encryption, services.PlatformSettingsEnvDefaults{})
	if err := platformSettingsSvc.EnsureRow(context.Background()); err != nil {
		t.Fatalf("ensure test platform settings row: %v", err)
	}
	platformConfigView := handlers.PlatformConfigView{
		PlatformName: "Infra Hub Center", VMMonitorInterval: "60s", VMMonitorRetentionDays: 30,
		DockerMetricsInterval: "15s", DatabaseMetricsInterval: "15s", DatabaseMetricsRetentionDays: 7,
		ObjectStorageMetricsInterval: "60s", AlertEvalInterval: "30s",
		AccessTokenTTLMinutes: 15, RefreshTokenTTLDays: 7, CookieSecure: false,
		LoginRateLimitAttempts: 1000, LoginRateLimitWindow: "1m", MaxRequestBodyBytes: 10 * 1024 * 1024,
	}

	handler := server.NewRouter(server.Dependencies{
		Pool: pool, Store: store, Tokens: tokens, Auth: auth, Authz: authz, Audit: audit,
		Workspaces: workspaceSvc, Resources: resourceSvc, VMs: vmSvc, Access: accessSvc,
		SSHKeyCredentials: sshKeyCredentialSvc, HostKeys: hostKeySvc, SSH: sshSvc, Discovery: discoverySvc,
		SSHConnectTimeout: connectTimeout,
		MonitorScheduler:  scheduler, MonitorStaleAfter: 5 * time.Minute,
		Packages: packageSvc, PackageScheduler: packageScheduler,
		ExternalPackages: externalPackageSvc, SMTPTimeout: time.Second,
		DockerScheduler: dockerScheduler, DockerMetricsCache: dockerCache,
		DockerStaleAfter: time.Minute, DockerStreamInterval: 200 * time.Millisecond,
		DockerAccess:      dockerAccessSvc,
		MonitoringFolders: monitoringFolderSvc, MonitoringDashboards: monitoringDashboardSvc,
		K8sClusters: k8sClusterSvc, K8sAgentHub: k8sAgentHubSvc, K8sAgentTokens: k8sAgentTokenSvc,
		K8s: k8sSvc, K8sScheduler: k8sScheduler,
		DockerAgentHub: dockerAgentHubSvc, DockerAgentTokens: dockerAgentTokenSvc,
		DockerHosts: dockerHostSvc, DockerHostAgentTokens: dockerHostAgentTokenSvc,
		DockerAgent: dockerAgentSvc, DockerAgentInstall: dockerAgentInstallSvc,
		VMAgentHub: vmAgentHubSvc, VMAgentTokens: vmAgentTokenSvc, VMAgent: vmAgentSvc, VMAgentInstall: vmAgentInstallSvc,
		DockerLogRetention: logRetention, K8sLogRetention: logRetention,
		UpdatePlans: updatePlanSvc, OSUpdates: osUpdateSvc,
		UpdateExecution: updateExecutionSvc, UpdateWorker: updateWorker,
		RebootExecution: rebootExecutionSvc, RebootWorker: rebootWorker,
		Databases: databaseSvc, DatabaseMetricsScheduler: databaseMetricsScheduler, DatabaseDeepMetricsScheduler: databaseDeepMetricsScheduler,
		DatabaseCredentials: databaseCredentialSvc, DatabaseMetricsCache: databaseCache,
		DatabaseDeepMetricsCache: databaseDeepCache, DatabaseFastThresholds: databaseThresholds, DatabasePerfThresholds: databasePerfThresholds,
		DatabaseStaleAfter: time.Minute, DatabaseStreamInterval: 200 * time.Millisecond,
		DatabaseConnectTimeout: connectTimeout, DatabaseCommandTimeout: commandTimeout,
		DatabaseBrowser: databaseBrowserSvc, DatabaseConnectionLimiter: databaseConnectionLimiter,
		DatabaseOperations: databaseOperationSvc, DatabaseOperationWorker: databaseOperationWorker,
		Alerts: alertSvc, AlertRules: alertRuleSvc, NotificationPolicies: notificationPolicySvc, Notifications: notificationSvc, AlertStreamInterval: 200 * time.Millisecond,
		ObjectStorages: objectStorageSvc, ObjectStorageCredentials: objectStorageCredentialSvc, ObjectStorageMetricsCache: objectStorageCache,
		ObjectStorageConnectionTimeout: 2 * time.Second,
		ObjectStorageBrowser:           objectStorageBrowserSvc,
		ObjectStorageMaxPageSize:       200,
		ObjectStoragePreviewMaxBytes:   5 * 1024 * 1024,
		ObjectStorageDownloadURLTTL:    5 * time.Minute,
		CookieSecure:                   false, FrontendOrigin: "http://localhost:3000",
		// Generous test-only values: a real request body limit and login
		// rate limit both apply in production (see router.go), but must
		// never be tight enough to make an unrelated test flaky just
		// because it happens to log in more than once.
		MaxRequestBodyBytes: 10 * 1024 * 1024, LoginRateLimitAttempts: 1000, LoginRateLimitWindow: time.Minute,
		AuditQuery: auditQuerySvc, UserPreferences: userPreferencesSvc, PlatformConfig: platformConfigView,
		PlatformSettings: platformSettingsSvc,
	})

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return &testEnv{
		baseURL: srv.URL, pool: pool, store: store, audit: audit, authz: authz, auth: auth, tokens: tokens,
		workspaces: workspaceSvc, resources: resourceSvc, vms: vmSvc, access: accessSvc,
		sshKeyCredentials: sshKeyCredentialSvc, hostKeys: hostKeySvc, ssh: sshSvc, discovery: discoverySvc,
		monitoring: monitoringSvc, scheduler: scheduler,
		packages: packageSvc, packageScheduler: packageScheduler,
		docker: dockerSvc, dockerScheduler: dockerScheduler, dockerCache: dockerCache, dockerAccess: dockerAccessSvc,
		k8sClusters: k8sClusterSvc, k8sAgentHub: k8sAgentHubSvc, k8sAgentTokens: k8sAgentTokenSvc, k8s: k8sSvc, k8sDiscovery: k8sDiscoverySvc, k8sScheduler: k8sScheduler,
		dockerAgentHub: dockerAgentHubSvc, dockerAgentTokens: dockerAgentTokenSvc, dockerAgent: dockerAgentSvc, dockerAgentInstall: dockerAgentInstallSvc,
		vmAgentHub: vmAgentHubSvc, vmAgentTokens: vmAgentTokenSvc, vmAgent: vmAgentSvc, vmAgentInstall: vmAgentInstallSvc,
		dockerLogCapture: dockerLogCaptureSvc, dockerLogRetentionSvc: dockerLogRetentionSvc,
		k8sLogCapture: k8sLogCaptureSvc, k8sLogRetentionSvc: k8sLogRetentionSvc,
		osUpdates: osUpdateSvc, updatePlans: updatePlanSvc,
		updateExecution: updateExecutionSvc, updateWorker: updateWorker,
		rebootExecution: rebootExecutionSvc, rebootWorker: rebootWorker,
		databases: databaseSvc, databaseCredentials: databaseCredentialSvc,
		databaseMetrics: databaseMetricsSvc, databaseCache: databaseCache,
		databaseDeepMetrics: databaseDeepMetricsSvc, databaseDeepCache: databaseDeepCache,
		databaseOperations: databaseOperationSvc,
		alertEngine:        alertEngine, alertRules: alertRuleSvc, notificationPolicies: notificationPolicySvc,
		objectStorages: objectStorageSvc, objectStorageCredentials: objectStorageCredentialSvc,
		objectStorageMetrics: objectStorageMetricsSvc, objectStorageCache: objectStorageCache,
		objectStorageDeepMetrics: objectStorageDeepMetricsSvc, objectStorageDeepCache: objectStorageDeepCache,
		objectStorageBrowser: objectStorageBrowserSvc,
		userPreferences:      userPreferencesSvc,
	}
}

// --- fixtures ---

func uniqueEmail(t *testing.T, prefix string) string {
	t.Helper()
	return prefix + "+" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12] + "@security-test.local"
}

func (e *testEnv) createAdmin(t *testing.T) (email, password string) {
	t.Helper()
	email = uniqueEmail(t, "admin")
	password = "AdminPassw0rd!23"
	if _, err := e.auth.CreateUserWithRole(context.Background(), email, "Test Admin", password, services.RoleAdmin); err != nil {
		t.Fatalf("create admin fixture: %v", err)
	}
	return email, password
}

func (e *testEnv) createMember(t *testing.T) (email, password string, userID uuid.UUID) {
	t.Helper()
	email = uniqueEmail(t, "member")
	password = "MemberPassw0rd!23"
	u, err := e.auth.CreateUserWithRole(context.Background(), email, "Test Member", password, services.RoleMember)
	if err != nil {
		t.Fatalf("create member fixture: %v", err)
	}
	return email, password, u.ID
}

func (e *testEnv) createWorkspace(t *testing.T) uuid.UUID {
	t.Helper()
	w, err := e.store.CreateWorkspace(context.Background(), generated.CreateWorkspaceParams{Name: "test-workspace-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("create workspace fixture: %v", err)
	}
	return w.ID
}

// createVM creates a resource+vms row under workspaceID.
func (e *testEnv) createVM(t *testing.T, workspaceID uuid.UUID) uuid.UUID {
	t.Helper()
	res, err := e.store.CreateResource(context.Background(), generated.CreateResourceParams{
		WorkspaceID:  workspaceID,
		Name:         "test-vm-" + uuid.NewString(),
		ResourceType: "VM",
	})
	if err != nil {
		t.Fatalf("create resource fixture: %v", err)
	}
	if _, err := e.store.CreateVM(context.Background(), generated.CreateVMParams{
		ResourceID: res.ID,
		Hostname:   res.Name,
		Address:    "10.0.0.1",
		SshPort:    22,
	}); err != nil {
		t.Fatalf("create vm fixture: %v", err)
	}
	return res.ID
}

// attachSSHKeyCredential creates a new named SSH key credential in
// workspaceID from keyPEM and attaches it to vm (a VM resource ID),
// entirely through the service layer -- the shared fixture shortcut every
// test that just needs a *working* credential uses. The HTTP surface for
// actually creating/attaching credentials (POST /api/ssh-key-credentials,
// PATCH /api/vms/{id}) is exercised directly by ssh_key_credential_test.go
// and the relevant tests in ssh_test.go/vm_console_test.go.
func (e *testEnv) attachSSHKeyCredential(t *testing.T, workspaceID, vm uuid.UUID, keyPEM string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	creator, err := e.auth.CreateUserWithRole(ctx, uniqueEmail(t, "cred-owner"), "Credential Owner", "Passw0rd!234", services.RoleAdmin)
	if err != nil {
		t.Fatalf("create credential-owner fixture: %v", err)
	}
	cred, err := e.sshKeyCredentials.Create(ctx, workspaceID, "test-key-"+uuid.NewString(), []byte(keyPEM), creator.ID)
	if err != nil {
		t.Fatalf("create ssh key credential fixture: %v", err)
	}
	vmRow, err := e.store.GetVMByResourceID(ctx, vm)
	if err != nil {
		t.Fatalf("load vm fixture: %v", err)
	}
	if err := e.store.SetVMSSHKeyCredentialID(ctx, generated.SetVMSSHKeyCredentialIDParams{
		ID: vmRow.ID, SshKeyCredentialID: pgutil.NullUUID(&cred.ID),
	}); err != nil {
		t.Fatalf("attach ssh key credential fixture: %v", err)
	}
	return cred.ID
}

// resourceName loads a resource's current display name -- Step 22's delete
// endpoints require it as confirmation_name, so any test fixture created
// with a randomized name (e.g. createDatabaseFixture, createObjectStorage-
// Fixture) needs this to build a valid delete request body.
func (e *testEnv) resourceName(t *testing.T, resourceID uuid.UUID) string {
	t.Helper()
	res, err := e.store.GetResourceByID(context.Background(), resourceID)
	if err != nil {
		t.Fatalf("load resource name for %s: %v", resourceID, err)
	}
	return res.Name
}

func (e *testEnv) grantDirectVMAccess(t *testing.T, userID, vmID uuid.UUID, permissions ...string) {
	t.Helper()
	for _, p := range permissions {
		perm, err := e.store.GetPermissionByName(context.Background(), p)
		if err != nil {
			t.Fatalf("load permission %s: %v", p, err)
		}
		if err := e.store.GrantResourcePermission(context.Background(), generated.GrantResourcePermissionParams{
			ResourceID: vmID, UserID: userID, PermissionID: perm.ID,
		}); err != nil {
			t.Fatalf("grant direct access: %v", err)
		}
	}
}

func (e *testEnv) addWorkspaceMember(t *testing.T, workspaceID, userID uuid.UUID) {
	t.Helper()
	if err := e.store.AddWorkspaceMember(context.Background(), generated.AddWorkspaceMemberParams{WorkspaceID: workspaceID, UserID: userID}); err != nil {
		t.Fatalf("add workspace member: %v", err)
	}
}

// --- HTTP helpers ---

func newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 5 * time.Second}
}

func (e *testEnv) login(t *testing.T, client *http.Client, email, password string) (*http.Response, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	resp, err := client.Post(e.baseURL+"/api/auth/login", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	return resp, decodeJSON(t, resp)
}

func decodeJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return map[string]any{}
	}
	return out
}

func (e *testEnv) get(t *testing.T, client *http.Client, path string) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := client.Get(e.baseURL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp, decodeJSON(t, resp)
}

func (e *testEnv) do(t *testing.T, client *http.Client, method, path string, body any) (*http.Response, map[string]any) {
	t.Helper()
	var reader *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = strings.NewReader(string(b))
	} else {
		reader = strings.NewReader("")
	}
	req, err := http.NewRequest(method, e.baseURL+path, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp, decodeJSON(t, resp)
}

// === 1-4: login ===

func TestLogin_AdminSuccess(t *testing.T) {
	e := setup(t)
	email, password := e.createAdmin(t)
	client := newClient()

	resp, body := e.login(t, client, email, password)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body["role"] != "ADMIN" {
		t.Errorf("role = %v, want ADMIN", body["role"])
	}
}

func TestLogin_MemberSuccess(t *testing.T) {
	e := setup(t)
	email, password, _ := e.createMember(t)
	client := newClient()

	resp, body := e.login(t, client, email, password)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body["role"] != "MEMBER" {
		t.Errorf("role = %v, want MEMBER", body["role"])
	}
}

func TestLogin_InvalidPassword(t *testing.T) {
	e := setup(t)
	email, _ := e.createAdmin(t)
	client := newClient()

	resp, body := e.login(t, client, email, "wrong-password")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if body["error"] != "Invalid email or password." {
		t.Errorf("error = %v, want generic message", body["error"])
	}
}

func TestLogin_DisabledUser(t *testing.T) {
	e := setup(t)
	email, password, userID := e.createMember(t)
	if err := e.store.DeactivateUser(context.Background(), userID); err != nil {
		t.Fatalf("deactivate user: %v", err)
	}
	client := newClient()

	resp, body := e.login(t, client, email, password)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	// Same generic message as a wrong password -- must not disclose that
	// the account exists but is disabled.
	if body["error"] != "Invalid email or password." {
		t.Errorf("error = %v, want generic message", body["error"])
	}
}

// === 5: expired token ===

func TestRequireAuthentication_ExpiredToken(t *testing.T) {
	e := setup(t)
	_, _, userID := e.createMember(t)

	// A negative TTL back-dates the token's exp claim to before its iat, so
	// it's already expired the moment it's issued -- deterministic, no
	// sleep-and-hope-the-clock-cooperates required.
	expiredTokens := services.NewTokenService(testJWTSecret, -1*time.Minute)
	token, err := expiredTokens.IssueAccessToken(userID, services.RoleMember)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, e.baseURL+"/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for expired token", resp.StatusCode)
	}
}

// === 6-7: refresh, logout ===

func TestRefresh_RotatesTokenAndInvalidatesOld(t *testing.T) {
	e := setup(t)
	email, password := e.createAdmin(t)
	client := newClient()
	e.login(t, client, email, password)

	resp, _ := e.do(t, client, http.MethodPost, "/api/auth/refresh", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status = %d, want 200", resp.StatusCode)
	}

	// The new session must still work.
	meResp, _ := e.get(t, client, "/api/auth/me")
	if meResp.StatusCode != http.StatusOK {
		t.Fatalf("/me after refresh = %d, want 200", meResp.StatusCode)
	}
}

func TestLogout_RevokesSession(t *testing.T) {
	e := setup(t)
	email, password := e.createAdmin(t)
	client := newClient()
	e.login(t, client, email, password)

	logoutResp, _ := e.do(t, client, http.MethodPost, "/api/auth/logout", nil)
	if logoutResp.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d, want 200", logoutResp.StatusCode)
	}

	// Refreshing with the now-revoked refresh token cookie must fail.
	refreshResp, _ := e.do(t, client, http.MethodPost, "/api/auth/refresh", nil)
	if refreshResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refresh after logout = %d, want 401", refreshResp.StatusCode)
	}
}

// === 8-14, 20-23: VM authorization matrix ===

func TestVMAccess_AdminSeesAllVMs(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/vms/"+vm.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin GET vm = %d, want 200", resp.StatusCode)
	}
	if body["access_source"] != "ADMIN" {
		t.Errorf("access_source = %v, want ADMIN", body["access_source"])
	}
}

func TestVMAccess_MemberDeniedUnauthorizedVM_NoLeak(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)

	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/vms/"+vm.String())
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized vm status = %d, want 404 (existence must not be disclosed)", resp.StatusCode)
	}
	for _, leaky := range []string{"address", "hostname", "name", "project"} {
		if _, present := body[leaky]; present {
			t.Errorf("404 response leaked field %q: %v", leaky, body)
		}
	}
}

func TestVMAccess_DirectGrant(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/vms/"+vm.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("directly-granted vm status = %d, want 200", resp.StatusCode)
	}
	if body["access_source"] != "DIRECT" {
		t.Errorf("access_source = %v, want DIRECT", body["access_source"])
	}
	perms, _ := body["permissions"].([]any)
	if len(perms) != 1 || perms[0] != services.PermVMView {
		t.Errorf("permissions = %v, want only vm.view (vm.connect was not granted)", perms)
	}
}

func TestVMAccess_GroupGrant(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	group := e.createWorkspace(t)
	vmInGroup := e.createVM(t, group)
	vmOutsideGroup := e.createVM(t, project)

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.addWorkspaceMember(t, group, memberID)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vmInGroup.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("group-granted vm status = %d, want 200", resp.StatusCode)
	}

	resp2, _ := e.get(t, client, "/api/vms/"+vmOutsideGroup.String())
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("vm outside group status = %d, want 404", resp2.StatusCode)
	}
}

func TestVMAccess_RevokeDirect(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	resp, _ := e.get(t, memberClient, "/api/vms/"+vm.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("precondition: member should see vm, got %d", resp.StatusCode)
	}

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	revokeResp, _ := e.do(t, adminClient, http.MethodDelete, "/api/users/"+memberID.String()+"/vm-access/"+vm.String(), nil)
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", revokeResp.StatusCode)
	}

	resp2, _ := e.get(t, memberClient, "/api/vms/"+vm.String())
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("after revoke, status = %d, want 404", resp2.StatusCode)
	}
}

func TestVMAccess_RemoveGroupMembership_DirectSurvives(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	group := e.createWorkspace(t)
	vmInGroup := e.createVM(t, group)
	vmDirect := e.createVM(t, project)

	adminEmail, adminPassword := e.createAdmin(t)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.addWorkspaceMember(t, group, memberID)
	e.grantDirectVMAccess(t, memberID, vmDirect, services.PermVMView)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	removeResp, _ := e.do(t, adminClient, http.MethodDelete, "/api/workspaces/"+group.String()+"/members/"+memberID.String(), nil)
	if removeResp.StatusCode != http.StatusOK {
		t.Fatalf("remove workspace member status = %d, want 200", removeResp.StatusCode)
	}

	// #13: group-derived access is gone.
	resp, _ := e.get(t, memberClient, "/api/vms/"+vmInGroup.String())
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("group-derived vm after removal = %d, want 404", resp.StatusCode)
	}

	// #14: direct access to a different VM is untouched.
	resp2, _ := e.get(t, memberClient, "/api/vms/"+vmDirect.String())
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("direct-access vm after group removal = %d, want 200", resp2.StatusCode)
	}
}

func TestMyAccess_OnlyAuthorizedVMs(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	authorizedVM := e.createVM(t, project)
	_ = e.createVM(t, project) // unauthorized, must not appear

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, authorizedVM, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/my-access")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("my-access status = %d, want 200", resp.StatusCode)
	}
	vms, _ := body["vms"].([]any)
	if len(vms) != 1 {
		t.Fatalf("my-access returned %d VMs, want exactly 1 (the authorized one)", len(vms))
	}
	first := vms[0].(map[string]any)
	if first["id"] != authorizedVM.String() {
		t.Errorf("my-access VM id = %v, want %v", first["id"], authorizedVM)
	}
}

func TestMyAccess_EmptyWhenNoGrants(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/my-access")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	vms, _ := body["vms"].([]any)
	if len(vms) != 0 {
		t.Fatalf("vms = %v, want empty", vms)
	}
}

// === 15-19: admin-only endpoints denied to members ===

func TestAdminAPI_MemberForbidden(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, memberID := e.createMember(t)
	project := e.createWorkspace(t)
	group := e.createWorkspace(t)
	vm := e.createVM(t, project)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	cases := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"list users", http.MethodGet, "/api/users", nil},
		{"create user", http.MethodPost, "/api/users", map[string]string{"name": "X", "email": uniqueEmail(t, "x"), "role": "MEMBER"}},
		{"get user", http.MethodGet, "/api/users/" + memberID.String(), nil},
		{"grant vm access", http.MethodPost, "/api/users/" + memberID.String() + "/vm-access", map[string]any{"vm_id": vm.String(), "permissions": []string{"vm.view"}}},
		{"add workspace member", http.MethodPost, "/api/workspaces/" + group.String() + "/members", map[string]string{"user_id": memberID.String()}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := e.do(t, client, tc.method, tc.path, tc.body)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s %s = %d, want 403", tc.method, tc.path, resp.StatusCode)
			}
		})
	}
}

func TestAccessAPI_GrantableVMPermissions_ExcludesUnimplemented(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)
	_, _, memberID := e.createMember(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/users/"+memberID.String()+"/vm-access", map[string]any{
		"vm_id":       vm.String(),
		"permissions": []string{"vm.execute"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("granting vm.execute = %d, want 400 (not implemented yet)", resp.StatusCode)
	}
	if body["error"] == nil {
		t.Errorf("expected an error message, got %v", body)
	}
}

// === Workspaces, VMs ===

func TestWorkspaces_CreateAsAdmin_MemberForbidden(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	memberEmail, memberPassword, _ := e.createMember(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	name := "test-workspace-" + uuid.NewString()
	resp, body := e.do(t, adminClient, http.MethodPost, "/api/workspaces", map[string]string{"name": name, "description": "d"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("admin create workspace = %d, want 201", resp.StatusCode)
	}
	if body["name"] != name {
		t.Errorf("name = %v, want %v", body["name"], name)
	}

	// Unlike the old Project tier, a Workspace name is not required to be
	// unique (see migrations/043_workspaces.sql's design note) -- creating
	// a second workspace with the same name must succeed, not 409.
	dupResp, _ := e.do(t, adminClient, http.MethodPost, "/api/workspaces", map[string]string{"name": name})
	if dupResp.StatusCode != http.StatusCreated {
		t.Errorf("duplicate workspace name = %d, want 201 (workspace names are not unique)", dupResp.StatusCode)
	}

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	memberResp, _ := e.do(t, memberClient, http.MethodPost, "/api/workspaces", map[string]string{"name": "member-workspace-" + uuid.NewString()})
	if memberResp.StatusCode != http.StatusForbidden {
		t.Errorf("member create workspace = %d, want 403", memberResp.StatusCode)
	}
}

// TestVM_Create_UnknownWorkspace_NotFound proves the backend validates
// workspace_id itself, never trusting the frontend's dropdown -- creating
// a VM against a nonexistent workspace must be rejected, not silently
// accepted.
func TestVM_Create_UnknownWorkspace_NotFound(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/vms", map[string]any{
		"workspace_id": uuid.NewString(), "name": "orphan-vm", "address": "10.0.0.5",
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("create VM against unknown workspace = %d, want 404", resp.StatusCode)
	}
	if body["error"] == nil {
		t.Errorf("expected an error message, got %v", body)
	}
}

func TestVM_Create_StartsUnknown_NoFakeData(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/vms", map[string]any{
		"workspace_id": project.String(), "name": "new-vm", "address": "10.0.0.9", "username": "ubuntu", "ssh_port": 22,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create vm = %d, want 201", resp.StatusCode)
	}
	if body["status"] != "UNKNOWN" {
		t.Errorf("status = %v, want UNKNOWN (registering a VM must never mark it ONLINE)", body["status"])
	}
	for _, discoveryField := range []string{"os_name", "os_version", "kernel_version", "architecture", "cpu_cores"} {
		if v, present := body[discoveryField]; present && v != nil {
			t.Errorf("discovery field %q = %v, want absent/null (no discovery has run)", discoveryField, v)
		}
	}
}

func TestVM_DeactivatedWorkspace_GrantsNoAccess(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	vm := e.createVM(t, workspace)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.addWorkspaceMember(t, workspace, memberID)
	adminEmail, adminPassword := e.createAdmin(t)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	preResp, _ := e.get(t, memberClient, "/api/vms/"+vm.String())
	if preResp.StatusCode != http.StatusOK {
		t.Fatalf("precondition: active workspace should grant access, got %d", preResp.StatusCode)
	}

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	deactivateResp, _ := e.do(t, adminClient, http.MethodPatch, "/api/workspaces/"+workspace.String(), map[string]any{"is_active": false})
	if deactivateResp.StatusCode != http.StatusOK {
		t.Fatalf("deactivate workspace = %d, want 200", deactivateResp.StatusCode)
	}

	postResp, _ := e.get(t, memberClient, "/api/vms/"+vm.String())
	if postResp.StatusCode != http.StatusNotFound {
		t.Errorf("vm access via deactivated workspace = %d, want 404 (deactivated workspace must not grant access)", postResp.StatusCode)
	}
}

func TestVM_Deactivated_CannotBeNewlyAccessed(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	deactivateResp, _ := e.do(t, adminClient, http.MethodPatch, "/api/vms/"+vm.String(), map[string]any{"status": "DISABLED"})
	if deactivateResp.StatusCode != http.StatusOK {
		t.Fatalf("deactivate vm = %d, want 200", deactivateResp.StatusCode)
	}

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	resp, _ := e.get(t, memberClient, "/api/vms/"+vm.String())
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("access to deactivated vm (even with an existing grant) = %d, want 404", resp.StatusCode)
	}
}

func TestAudit_ManagementEventsRecorded(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	wsResp, wsBody := e.do(t, client, http.MethodPost, "/api/workspaces", map[string]string{"name": "audit-test-workspace-" + uuid.NewString()})
	if wsResp.StatusCode != http.StatusCreated {
		t.Fatalf("create workspace = %d", wsResp.StatusCode)
	}
	workspaceID, _ := uuid.Parse(wsBody["id"].(string))

	vmResp, vmBody := e.do(t, client, http.MethodPost, "/api/vms", map[string]any{
		"workspace_id": workspaceID.String(), "name": "audit-test-vm", "address": "10.0.0.7",
	})
	if vmResp.StatusCode != http.StatusCreated {
		t.Fatalf("create vm = %d", vmResp.StatusCode)
	}
	vmID, _ := uuid.Parse(vmBody["id"].(string))

	assertAuditEventExists(t, e, "WORKSPACE", workspaceID, services.AuditWorkspaceCreated)
	assertAuditEventExists(t, e, "VM", vmID, services.AuditVMCreated)

	_, _, memberID := e.createMember(t)
	grantResp, _ := e.do(t, client, http.MethodPost, "/api/users/"+memberID.String()+"/vm-access", map[string]any{
		"vm_id": vmID.String(), "permissions": []string{"vm.view"},
	})
	if grantResp.StatusCode != http.StatusOK {
		t.Fatalf("grant access = %d", grantResp.StatusCode)
	}
	assertAuditEventExists(t, e, "VM", vmID, services.AuditVMAccessGranted)
}

func assertAuditEventExists(t *testing.T, e *testEnv, resourceType string, resourceID uuid.UUID, action string) {
	t.Helper()
	// A generous limit: Step 16's notification fan-out can append many
	// NOTIFICATION_SENT rows (one per authorized recipient) for the same
	// alert resource_id after its single ALERT_CREATED row, so a small
	// limit here risks paging the very event a caller is asserting on
	// out of the "most recent N" window it queries.
	logs, err := e.store.ListAuditLogsByResource(context.Background(), generated.ListAuditLogsByResourceParams{
		ResourceID: pgutil.NullUUID(&resourceID), Limit: 500,
	})
	if err != nil {
		t.Fatalf("query audit logs: %v", err)
	}
	for _, l := range logs {
		if l.Action == action {
			return
		}
	}
	t.Errorf("no %s audit log found for %s %s", action, resourceType, resourceID)
}
