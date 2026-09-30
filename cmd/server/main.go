// Command server runs the Infra Hub Center backend HTTP API.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"vmcontrolcenter/backend/internal/config"
	"vmcontrolcenter/backend/internal/database"
	"vmcontrolcenter/backend/internal/handlers"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/server"
	"vmcontrolcenter/backend/internal/services"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("server exited with error", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := database.NewPool(ctx, cfg.DatabaseURL, database.PoolConfig{
		MaxConns:       cfg.DBMaxConns,
		MinConns:       cfg.DBMinConns,
		ConnectTimeout: cfg.DBConnectTimeout,
	})
	if err != nil {
		return err
	}
	defer pool.Close()

	logger.Info("database connection established",
		"max_conns", cfg.DBMaxConns,
		"min_conns", cfg.DBMinConns,
	)

	store := repository.New(pool)
	tokens := services.NewTokenService(cfg.JWTSecret, cfg.AccessTokenTTL)
	authService := services.NewAuthService(store, tokens, cfg.RefreshTokenTTL)

	// Runtime admin bootstrap: if BOOTSTRAP_ADMIN_EMAIL/NAME/PASSWORD are
	// set, create that ADMIN account automatically on startup instead of
	// requiring a separate `go run ./cmd/bootstrap-admin` step -- the same
	// convention as e.g. Grafana's GF_SECURITY_ADMIN_* or Django's
	// DJANGO_SUPERUSER_* env vars. Unset (all three empty) is the default
	// and changes nothing; partially set is rejected as a likely typo
	// rather than silently ignored. Idempotent by construction
	// (AuthService.BootstrapAdmin no-ops once an admin exists), so these
	// env vars can stay set for the life of a deployment without every
	// later restart failing on its own prior success.
	if cfg.BootstrapAdminEmail != "" || cfg.BootstrapAdminName != "" || cfg.BootstrapAdminPassword != "" {
		if cfg.BootstrapAdminEmail == "" || cfg.BootstrapAdminName == "" || cfg.BootstrapAdminPassword == "" {
			return fmt.Errorf("BOOTSTRAP_ADMIN_EMAIL, BOOTSTRAP_ADMIN_NAME, and BOOTSTRAP_ADMIN_PASSWORD must all be set together, or all left unset")
		}
		created, admin, err := authService.BootstrapAdmin(ctx, cfg.BootstrapAdminEmail, cfg.BootstrapAdminName, cfg.BootstrapAdminPassword)
		if err != nil {
			return fmt.Errorf("bootstrap admin: %w", err)
		}
		if created {
			logger.Info("admin account created from BOOTSTRAP_ADMIN_* env vars", "id", admin.ID, "email", admin.Email)
		} else {
			logger.Info("admin bootstrap skipped: an admin account already exists")
		}
	}

	authz := services.NewAuthorizationService(store.Queries)
	audit := services.NewAuditService(store)
	workspaceService := services.NewWorkspaceService(store)
	resourceService := services.NewResourceService(store)
	vmService := services.NewVMService(store, authz)
	accessService := services.NewAccessService(store)

	encryption, err := services.NewEncryptionService(cfg.SSHCredentialEncryptionKey)
	if err != nil {
		return fmt.Errorf("SSH_CREDENTIAL_ENCRYPTION_KEY: %w", err)
	}
	sshKeyCredentialService := services.NewSSHKeyCredentialService(store, encryption)
	hostKeyService := services.NewHostKeyService(store)
	sshService := services.NewSSHService(store, sshKeyCredentialService, hostKeyService, cfg.SSHConnectTimeout)
	remoteExecutor := services.NewRemoteExecutor()
	discoveryService := services.NewVMDiscoveryService(store, sshService, remoteExecutor, cfg.SSHCommandTimeout)

	// Per-VM Docker agent (Docker+Kubernetes monitoring rework, Phase 1).
	// Mirrors the K8sAgentHub/K8sAgentTokenService/K8sService trio below
	// exactly, but install is a single automated SSH-based action
	// (DockerAgentInstallService) rather than a manifest the admin applies
	// by hand -- see docker_agent_install.go's doc comment. Constructed
	// early since DockerMetricsService/DockerLogCaptureService below both
	// take it to prefer agent-based collection over SSH when connected.
	dockerAgentHub := services.NewDockerAgentHub()
	dockerAgentTokenService := services.NewDockerAgentTokenService(store)
	dockerAgentService := services.NewDockerAgentService(store, dockerAgentHub, cfg.DockerAgentCommandTimeout)
	dockerAgentInstallService := services.NewDockerAgentInstallService(
		store, sshService, remoteExecutor, dockerAgentTokenService, dockerAgentHub, dockerAgentService,
		cfg.DockerAgentBackendURL, cfg.DockerAgentInstallTimeout,
	)

	// Docker Hosts: a standalone Docker agent target, mirroring the K8s
	// cluster trio below exactly -- no VM record, no SSH, connected purely
	// by running the agent's own published container image with a bearer
	// token (see services/docker_host.go's doc comment). Shares
	// dockerAgentHub above with VM-attached agents; DockerAgentHandler.Connect
	// tries both token services to resolve whichever kind of agent dialed in.
	dockerHostAgentTokenService := services.NewDockerHostAgentTokenService(store)
	dockerHostService := services.NewDockerHostService(store, dockerHostAgentTokenService)

	// VM Agent: a separate, push-based agent (migrations/052_vm_agent.sql)
	// running alongside the SSH-based monitoring/package schedulers above,
	// never replacing them -- see services/vm_agent_hub.go's doc comment.
	// VMAgentService and VMAgentHub are mutually referential (the hub calls
	// the service's HandleMetricsPush on every push; the service calls the
	// hub's SendCommand/StreamLogs/IsConnected), so construction is two
	// steps: build the service first (hub wired in after), then the hub
	// with a closure over the service, then complete the service via SetHub.
	vmAgentTokenService := services.NewVMAgentTokenService(store)
	vmAgentService := services.NewVMAgentService(store, cfg.VMAgentCommandTimeout)
	vmAgentHub := services.NewVMAgentHub(logger, vmAgentService.HandleMetricsPush)
	vmAgentService.SetHub(vmAgentHub)
	vmAgentInstallService := services.NewVMAgentInstallService(cfg.VMAgentBackendURL)

	healthThresholds := services.HealthThresholds{
		CPUWarning: cfg.VMCPUWarningPercent, CPUCritical: cfg.VMCPUCriticalPercent,
		MemoryWarning: cfg.VMMemoryWarningPercent, MemoryCritical: cfg.VMMemoryCriticalPercent,
		DiskWarning: cfg.VMDiskWarningPercent, DiskCritical: cfg.VMDiskCriticalPercent,
	}
	monitoringService := services.NewVMMonitoringService(store, sshService, remoteExecutor, cfg.SSHCommandTimeout, healthThresholds)
	monitorScheduler := services.NewMonitoringScheduler(store, monitoringService, cfg.VMMonitorInterval, cfg.VMMonitorWorkers, logger)
	retentionService := services.NewRetentionService(store, cfg.VMMonitorRetentionDays, logger)

	packageDetector := services.NewPackageManagerDetector(remoteExecutor, cfg.SSHCommandTimeout)
	packageFactory := services.NewPackageManagerFactory(remoteExecutor, cfg.PackageScanCommandTimeout)
	packageService := services.NewPackageService(store, sshService, packageDetector, packageFactory, cfg.PackageScanCommandTimeout)
	packageScheduler := services.NewPackageScanScheduler(store, packageService, cfg.PackageScanInterval, cfg.PackageScanWorkers, logger)
	externalPackageScanner := services.NewExternalPackageScanner(store, sshService, remoteExecutor, cfg.PackageScanCommandTimeout)
	// UserHandler builds a fresh InviteMailer per invite from live,
	// Owner-editable SMTP settings (services.PlatformSettingsService,
	// migration 047) instead of one fixed at startup -- see users.go's own
	// doc comment. cfg.SMTP* still seeds PlatformSettingsEnvDefaults below
	// as the fallback for anything not yet overridden through the UI.

	// Discovery (inventory) and metrics (docker stats) use the same
	// DockerClient shape but different per-command timeouts: discovery's
	// batched inspect commands can take longer on a VM with many
	// containers/images, while metrics' single `docker stats` command is
	// mandated to run on a short, frequent cadence (spec §34).
	dockerDiscoveryClient := services.NewDockerClient(remoteExecutor, cfg.PackageScanCommandTimeout)
	dockerMetricsClient := services.NewDockerClient(remoteExecutor, cfg.SSHCommandTimeout)
	dockerDiscoveryService := services.NewDockerDiscoveryService(store, sshService, dockerDiscoveryClient)
	dockerScanScheduler := services.NewDockerDiscoveryScheduler(store, dockerDiscoveryService, cfg.DockerScanInterval, cfg.DockerScanWorkers, logger)
	dockerMetricsCache := services.NewDockerMetricsCache()
	dockerMetricsService := services.NewDockerMetricsService(store, sshService, dockerMetricsClient, dockerMetricsCache, dockerAgentService)
	dockerMetricsScheduler := services.NewDockerMetricsScheduler(store, dockerMetricsService, cfg.DockerMetricsInterval, cfg.DockerMetricsWorkers, logger)
	dockerRetentionService := services.NewDockerRetentionService(store, cfg.DockerMetricsRetentionDays, logger)

	// The top-level Docker Monitoring/Logs section's Workspace-scoped
	// view-only access grants (this same table/service also covers K8s
	// permissions -- see services.DockerAccessService's doc comment).
	dockerAccessService := services.NewDockerAccessService(store, workspaceService)

	// Monitoring/Logs Folder > Dashboard: four independent trees under
	// Workspace (Monitoring>Docker, Monitoring>Kubernetes, Logs>Docker,
	// Logs>Kubernetes), each Dashboard binding one VM/K8sCluster plus a
	// multi-resource selection (see services/monitoring_dashboards.go).
	// Also grantable directly (FOLDER/DASHBOARD scope) via
	// dockerAccessService above.
	monitoringFolderService := services.NewMonitoringFolderService(store)
	monitoringDashboardService := services.NewMonitoringDashboardService(store, authz)

	// Step 25: standalone Kubernetes clusters, connected via an in-cluster
	// agent the admin installs themselves (see /k8s-agent at the repo
	// root) rather than an uploaded kubeconfig -- InfraHub never holds a
	// cluster credential of any kind. K8sAgentHub is the process-wide
	// registry of live agent WebSocket connections; K8sAgentTokenService
	// issues/verifies the bearer tokens an agent authenticates with.
	// Discovery mirrors Docker's own discovery/scheduler shape exactly
	// (see k8s_discovery.go's doc comment), just talking to the agent
	// instead of running `docker` over SSH.
	k8sAgentHub := services.NewK8sAgentHub()
	k8sAgentTokenService := services.NewK8sAgentTokenService(store)
	k8sClusterService := services.NewK8sClusterService(store, k8sAgentTokenService)
	k8sService := services.NewK8sService(store, k8sAgentHub, cfg.K8sConnectTimeout)
	k8sDiscoveryService := services.NewK8sDiscoveryService(store, k8sService)
	k8sScanScheduler := services.NewK8sDiscoveryScheduler(store, k8sDiscoveryService, cfg.K8sScanInterval, cfg.K8sScanWorkers, logger)

	// Log history (a later addition to Step 24/25): a periodic, bounded
	// background capture -- independent of the live-tail WebSockets, which
	// persist nothing -- keeps up to *_LOG_RETENTION_DAYS of searchable
	// Docker container / K8s pod log history. See
	// services/docker_log_capture.go and services/k8s_log_capture.go.
	//
	// logArchiver (LOG_ARCHIVE_BACKEND) is shared by all three retention
	// services below -- built once, here, so a misconfigured
	// volume path/S3 bucket fails the server at startup, not on the first
	// retention sweep that happens to find rows to archive. Defaults to a
	// no-op ("none"): existing behavior (rows are just deleted) is
	// unchanged unless an operator opts in. See services/log_archive.go.
	logArchiver, err := services.NewLogArchiver(services.LogArchiveConfig{
		Backend: cfg.LogArchiveBackend, VolumePath: cfg.LogArchiveVolumePath,
		S3Bucket: cfg.LogArchiveS3Bucket, S3Region: cfg.LogArchiveS3Region, S3Endpoint: cfg.LogArchiveS3Endpoint,
		S3Prefix: cfg.LogArchiveS3Prefix, S3AccessKeyID: cfg.LogArchiveS3AccessKeyID, S3SecretAccessKey: cfg.LogArchiveS3SecretAccessKey,
	})
	if err != nil {
		logger.Error("failed to configure log archiver", "error", err)
		os.Exit(1)
	}

	dockerLogRetention := time.Duration(cfg.DockerLogRetentionDays) * 24 * time.Hour
	dockerLogCaptureService := services.NewDockerLogCaptureService(store, sshService, remoteExecutor, cfg.SSHCommandTimeout, dockerLogRetention, dockerAgentService)
	dockerLogCaptureScheduler := services.NewDockerLogCaptureScheduler(store, dockerLogCaptureService, cfg.DockerLogCaptureInterval, cfg.DockerLogCaptureWorkers, logger)
	dockerLogRetentionService := services.NewDockerLogRetentionService(store, cfg.DockerLogRetentionDays, logArchiver, logger)

	k8sLogRetention := time.Duration(cfg.K8sLogRetentionDays) * 24 * time.Hour
	k8sLogCaptureService := services.NewK8sLogCaptureService(store, k8sService, k8sLogRetention)
	k8sLogCaptureScheduler := services.NewK8sLogCaptureScheduler(store, k8sLogCaptureService, cfg.K8sLogCaptureInterval, cfg.K8sLogCaptureWorkers, logger)
	k8sLogRetentionService := services.NewK8sLogRetentionService(store, cfg.K8sLogRetentionDays, logArchiver, logger)

	// Docker Host containers (the agent-only, no-SSH standalone hosts added
	// alongside VM Agent/K8s Agent) had no persisted log history at all --
	// see migration 057's own doc comment. This closes that gap the same
	// way, reusing the Docker retention policy/cadence (same concept, one
	// more table) -- see services/docker_host_log_capture.go.
	dockerHostLogCaptureService := services.NewDockerHostLogCaptureService(store, dockerAgentService, dockerLogRetention)
	dockerHostLogCaptureScheduler := services.NewDockerHostLogCaptureScheduler(store, dockerHostLogCaptureService, cfg.DockerLogCaptureInterval, cfg.DockerLogCaptureWorkers, logger)
	dockerHostLogRetentionService := services.NewDockerHostLogRetentionService(store, cfg.DockerLogRetentionDays, logArchiver, logger)

	// Update Center (Step 9): OS/kernel/reboot detection rides on the
	// existing package scan scheduler's cadence rather than a new ticker
	// (spec §67) -- SetOSUpdateService wires it in as a follow-up step
	// after every package scan cycle. Update planning has no background
	// loop at all: it only ever runs in direct response to an admin
	// request (create/validate/approve/cancel).
	osUpdateService := services.NewOSUpdateService(store, sshService, remoteExecutor, cfg.SSHCommandTimeout)
	packageScheduler.SetOSUpdateService(osUpdateService)
	updatePlanService := services.NewUpdatePlanService(store, sshService, cfg.UpdateMetadataStaleAfter)

	// Update execution engine (Step 10): the one component in this project
	// that can actually change a remote VM. Reuses sshService/
	// remoteExecutor (Step 5, unchanged) and discoveryService/
	// monitoringService/packageService/dockerDiscoveryService/
	// osUpdateService (Steps 5-9, unchanged) wholesale for everything that
	// isn't unique to execution -- see docs/update-execution.md.
	updateExecutionService := services.NewUpdateExecutionService(
		store, sshService, remoteExecutor, updatePlanService,
		discoveryService, monitoringService, packageService, dockerDiscoveryService, osUpdateService, audit,
		cfg.SSHCommandTimeout, cfg.UpdateCommandTimeout, cfg.UpdateLogMaxBytes, cfg.MaxPackagesPerUpdatePlan,
	)
	updateExecutionWorker := services.NewUpdateExecutionWorker(updateExecutionService, cfg.UpdateWorkers, cfg.MaxConcurrentUpdates, logger)

	// Crash recovery (spec: "detect any operation left CONNECTING/RUNNING/
	// VERIFYING from an unclean prior shutdown and mark it INTERRUPTED --
	// never automatically resume") must run once, before the HTTP server
	// starts accepting requests and before the worker pool starts
	// dequeuing jobs, so a stale in-progress operation can never be acted
	// on as if it were still live.
	if recovered, err := updateExecutionService.RecoverInterruptedOperations(ctx); err != nil {
		logger.Error("failed to recover interrupted update operations at startup", "error", err)
	} else if recovered > 0 {
		logger.Warn("marked interrupted update operations from an unclean prior shutdown", "count", recovered)
	}

	// Controlled VM reboot (Step 11): the second and last component in
	// this project that can actually change a remote VM. Reuses every
	// rediscovery service above (Steps 5-9, unchanged) for pre/post-reboot
	// verification -- see docs/vm-reboot.md.
	rebootExecutionService := services.NewRebootExecutionService(
		store, sshService, remoteExecutor, discoveryService, monitoringService, packageService, dockerDiscoveryService, osUpdateService, audit,
		cfg.SSHCommandTimeout, cfg.RebootTimeout, cfg.RebootInitialWait, cfg.RebootMaxReconnectAttempts, cfg.UpdateLogMaxBytes,
	)
	rebootExecutionWorker := services.NewRebootExecutionWorker(rebootExecutionService, cfg.RebootWorkers, cfg.MaxConcurrentVMOperations, logger)

	if recovered, err := rebootExecutionService.RecoverInterruptedRebootOperations(ctx); err != nil {
		logger.Error("failed to recover interrupted reboot operations at startup", "error", err)
	} else if recovered > 0 {
		logger.Warn("marked interrupted reboot operations from an unclean prior shutdown", "count", recovered)
	}

	// Standalone database monitoring (strictly read-only): a database is a
	// first-class resource under a Project (optionally a Group), connected
	// directly via TCP/TLS -- never a VM child, never reached through SSH.
	databaseCredentialService := services.NewStandaloneDatabaseCredentialService(store, encryption)
	databaseService := services.NewDatabaseService(store, databaseCredentialService)
	databaseHealthThresholds := services.DatabaseHealthThresholds{
		ConnectionWarning: cfg.DatabaseConnectionWarningPct, ConnectionCritical: cfg.DatabaseConnectionCriticalPct,
		MemoryWarning: cfg.DatabaseMemoryWarningPct, MemoryCritical: cfg.DatabaseMemoryCriticalPct,
	}
	databaseMetricsCache := services.NewDatabaseMetricsCache()
	databaseMetricsService := services.NewDatabaseMetricsService(
		store, databaseCredentialService, databaseMetricsCache,
		cfg.DatabaseConnectionTimeout, cfg.DatabaseQueryTimeout, databaseHealthThresholds,
	)
	databaseMetricsScheduler := services.NewDatabaseMetricsScheduler(store, databaseMetricsService, cfg.DatabaseMetricsInterval, cfg.DatabaseMetricsWorkers, logger)
	databaseRetentionService := services.NewDatabaseRetentionService(store, cfg.DatabaseMetricsRetentionDays, cfg.DatabaseQueryMetricsRetentionDays, logger)

	// Advanced database performance monitoring, still strictly read-only:
	// a separate, slower "deep" cycle layered on top of the fast cycle --
	// query rankings, locks/waits, replication detail, storage growth.
	databasePerformanceThresholds := services.DatabasePerformanceThresholds{
		CacheHitWarning: cfg.DatabaseCacheHitWarningPct, CacheHitCritical: cfg.DatabaseCacheHitCriticalPct,
		LockWarningCount: int64(cfg.DatabaseLockWarningCount), SlowQueryMs: float64(cfg.DatabaseSlowQueryMs),
		GrowthWarningPercent: cfg.DatabaseGrowthWarningPercent,
	}
	databaseDeepMetricsCache := services.NewDatabaseDeepMetricsCache()
	databaseDeepMetricsService := services.NewDatabaseDeepMetricsService(
		store, databaseCredentialService, databaseDeepMetricsCache,
		cfg.DatabaseConnectionTimeout, cfg.DatabaseQueryTimeout, databasePerformanceThresholds,
		cfg.DatabaseQueryTextCapture, cfg.DatabaseQueryTextMaxBytes,
	)
	databaseDeepMetricsScheduler := services.NewDatabaseDeepMetricsScheduler(store, databaseDeepMetricsService, cfg.DatabaseDeepMetricsInterval, cfg.DatabaseDeepMetricsWorkers, logger)

	// One shared cap across BOTH the fast and deep monitoring cycles'
	// combined worker pools -- never lets this application's own
	// monitoring open more than DATABASE_MONITOR_MAX_CONNECTIONS
	// simultaneous connections to target databases, regardless of how many
	// scheduler workers are configured.
	databaseConnectionLimiter := services.NewDatabaseConnectionLimiter(cfg.DatabaseMonitorMaxConnections)
	databaseMetricsService.SetConnectionLimiter(databaseConnectionLimiter)
	databaseDeepMetricsService.SetConnectionLimiter(databaseConnectionLimiter)

	// Database browser: standalone/managed database read-only browsing and
	// exploration (schema/table/row for SQL engines, collections/documents
	// for MongoDB, keys/values for Redis/Valkey).
	databaseBrowserService := services.NewDatabaseBrowserService(store, databaseCredentialService, databaseConnectionLimiter)

	// Controlled database operations + admin remediation (Step 14):
	// Review -> Approve -> Execute -> Verify, on top of Step 13's
	// read-only monitoring. Admin-only end to end -- see docs/database-operations.md.
	databaseOperationService := services.NewDatabaseOperationService(
		store, databaseCredentialService, audit, cfg.DatabaseConnectionTimeout, cfg.DatabaseQueryTimeout,
		cfg.DatabaseOperationTimeout, databaseHealthThresholds, cfg.DatabaseOperationLogMaxBytes,
	)
	databaseOperationWorker := services.NewDatabaseOperationWorker(databaseOperationService, cfg.DatabaseOperationWorkers, cfg.MaxConcurrentDatabaseOperations, logger)
	if recovered, err := databaseOperationService.RecoverInterruptedDatabaseOperations(ctx); err != nil {
		logger.Error("failed to recover interrupted database operations at startup", "error", err)
	} else if recovered > 0 {
		logger.Warn("marked interrupted database operations from an unclean prior shutdown", "count", recovered)
	}

	// Standalone object storage monitoring (Step 17). Phase 1 built the
	// schema + adapter + CRUD + test-connection surface. Phase 2 adds the
	// fast metrics scheduler below, mirroring the Database fast-cycle
	// block's construction order exactly: credential/domain service,
	// cache, metrics service, scheduler, retention service, then the
	// shared connection limiter wired in last. Reuses the same
	// EncryptionService (SSH_CREDENTIAL_ENCRYPTION_KEY) as every other
	// credential store in this project.
	objectStorageCredentialService := services.NewStandaloneObjectStorageCredentialService(store, encryption)
	objectStorageService := services.NewObjectStorageService(store, objectStorageCredentialService)
	objectStorageMetricsCache := services.NewObjectStorageMetricsCache()
	objectStorageMetricsService := services.NewObjectStorageMetricsService(
		store, objectStorageCredentialService, objectStorageMetricsCache, cfg.ObjectStorageConnectionTimeout,
	)
	objectStorageMetricsScheduler := services.NewObjectStorageMetricsScheduler(
		store, objectStorageMetricsService, cfg.ObjectStorageMetricsInterval, cfg.ObjectStorageMetricsWorkers, logger,
	)
	objectStorageRetentionService := services.NewObjectStorageRetentionService(store, cfg.ObjectStorageMetricsRetentionDays, logger)

	// Its own cap, independent of DatabaseConnectionLimiter above -- never
	// lets object storage monitoring open more than
	// OBJECT_STORAGE_MONITOR_MAX_CONNECTIONS simultaneous S3 client
	// connections, regardless of OBJECT_STORAGE_METRICS_WORKERS.
	objectStorageConnectionLimiter := services.NewObjectStorageConnectionLimiter(cfg.ObjectStorageMonitorMaxConnections)
	objectStorageMetricsService.SetConnectionLimiter(objectStorageConnectionLimiter)

	// Standalone object storage deep metrics (Step 17 Phase 3): bucket
	// security facts (versioning/encryption/public-access/object-lock),
	// growth tracking, CloudWatch/bounded-listing bucket metrics, plus the
	// four OBJECT_STORAGE_* recommendation types -- layered on top of the
	// fast cycle above on its own, much less frequent cadence, exactly
	// like the Database deep-metrics block. Reuses the SAME
	// objectStorageCredentialService/objectStorageMetricsCache/
	// objectStorageConnectionLimiter constructed above -- deep and fast
	// cycles share one connection cap and one bucket-metrics cache, never
	// a second independent one.
	objectStorageDeepMetricsCache := services.NewObjectStorageDeepMetricsCache()
	objectStorageDeepMetricsService := services.NewObjectStorageDeepMetricsService(
		store, objectStorageCredentialService, objectStorageMetricsCache, objectStorageDeepMetricsCache,
		cfg.ObjectStorageConnectionTimeout, cfg.ObjectStorageGrowthWarningPercent, cfg.ObjectStorageErrorRateWarningPercent,
		cfg.ObjectStoragePublicAccessSeverity,
	)
	objectStorageDeepMetricsService.SetConnectionLimiter(objectStorageConnectionLimiter)
	objectStorageDeepMetricsScheduler := services.NewObjectStorageDeepMetricsScheduler(
		store, objectStorageDeepMetricsService, cfg.ObjectStorageDeepMetricsInterval, cfg.ObjectStorageDeepMetricsWorkers, logger,
	)

	// Standalone object storage browser (Step 17 Phase 4): read-only object
	// listing/prefix navigation, metadata, short-lived presigned-URL
	// download, and text/JSON preview. Reuses the same
	// objectStorageCredentialService constructed above -- no second
	// credential store. No scheduler/background loop of any kind: every
	// call here is directly, synchronously driven by an inbound HTTP
	// request.
	objectStorageBrowserService := services.NewObjectStorageBrowserService(store, objectStorageCredentialService)

	// Central alerts + notifications (Step 16): Metrics -> Rule
	// Evaluation -> Threshold -> Duration -> Deduplication -> Alert State
	// -> Notification, layered on top of every existing metrics source
	// (Steps 6/8/13) -- see docs/alerts.md.
	alertRuleService := services.NewAlertRuleService(store)
	alertService := services.NewAlertService(store, audit)
	notificationPolicyService := services.NewNotificationPolicyService(store)
	if err := notificationPolicyService.EnsureDefaultPolicy(ctx); err != nil {
		logger.Error("failed to ensure default notification policy at startup", "error", err)
	}
	notificationService := services.NewNotificationService(store, audit, cfg.AlertNotificationCooldown, cfg.AlertWebhookTimeout, int(cfg.AlertNotificationMaxRetries), services.EmailConfig{
		Host: cfg.SMTPHost, Port: cfg.SMTPPort, Username: cfg.SMTPUsername, Password: cfg.SMTPPassword,
		FromEmail: cfg.SMTPFromEmail, UseTLS: cfg.SMTPUseTLS, Timeout: cfg.SMTPTimeout,
	}, logger)
	alertEngine := services.NewAlertEngine(store, audit, notificationService, dockerAgentHub, k8sAgentHub, logger)
	alertRetentionService := services.NewAlertRetentionService(store, cfg.AlertRetentionDays, cfg.NotificationRetentionDays, logger)

	// Step 21: Operations/Audit Logs/Settings -- pure read/aggregation
	// layers over data and config this file already constructs above; see
	// each service/handler's own package doc for exactly what it reuses.
	auditQueryService := services.NewAuditQueryService(store)
	userPreferencesService := services.NewUserPreferencesService(store)
	platformConfigView := handlers.PlatformConfigView{
		PlatformName:                 "Infra Hub Center",
		VMMonitorInterval:            cfg.VMMonitorInterval.String(),
		VMMonitorRetentionDays:       cfg.VMMonitorRetentionDays,
		DockerMetricsInterval:        cfg.DockerMetricsInterval.String(),
		DatabaseMetricsInterval:      cfg.DatabaseMetricsInterval.String(),
		DatabaseMetricsRetentionDays: cfg.DatabaseMetricsRetentionDays,
		ObjectStorageMetricsInterval: cfg.ObjectStorageMetricsInterval.String(),
		AlertEvalInterval:            cfg.AlertEvalInterval.String(),
		AccessTokenTTLMinutes:        int32(cfg.AccessTokenTTL / time.Minute),
		RefreshTokenTTLDays:          int32(cfg.RefreshTokenTTL / (24 * time.Hour)),
		CookieSecure:                 cfg.CookieSecure,
		LoginRateLimitAttempts:       cfg.LoginRateLimitAttempts,
		LoginRateLimitWindow:         cfg.LoginRateLimitWindow.String(),
		MaxRequestBodyBytes:          cfg.MaxRequestBodyBytes,
	}

	// Owner-editable Sign-in Methods (GitHub/Google OAuth, SMTP) --
	// DB-backed (migration 047), read fresh on every use, falling back to
	// these exact .env values field-by-field for anything not yet
	// overridden via the UI -- see PlatformSettingsService's own doc
	// comment. EnsureRow creates the one settings row once, mirroring
	// NotificationPolicyService.EnsureDefaultPolicy below.
	platformSettingsService := services.NewPlatformSettingsService(store, encryption, services.PlatformSettingsEnvDefaults{
		GitHubClientID: cfg.GitHubClientID, GitHubClientSecret: cfg.GitHubClientSecret,
		GoogleClientID: cfg.GoogleClientID, GoogleClientSecret: cfg.GoogleClientSecret,
		SMTPHost: cfg.SMTPHost, SMTPPort: cfg.SMTPPort, SMTPUsername: cfg.SMTPUsername,
		SMTPPassword: cfg.SMTPPassword, SMTPFromEmail: cfg.SMTPFromEmail, SMTPUseTLS: cfg.SMTPUseTLS,
	})
	if err := platformSettingsService.EnsureRow(ctx); err != nil {
		return fmt.Errorf("ensure platform settings row: %w", err)
	}

	// All background loops share the same signal-cancellable ctx as the
	// HTTP server, and this WaitGroup blocks run() from returning until
	// they've actually finished draining -- not just fired off and
	// forgotten (Step 6 spec §5: "start with the backend... stop
	// gracefully... respect application context cancellation" -- Step 7's
	// package scan scheduler and Step 8's Docker schedulers follow the
	// exact same contract).
	var background sync.WaitGroup
	background.Add(24)
	go func() { defer background.Done(); monitorScheduler.Run(ctx) }()
	go func() { defer background.Done(); retentionService.Run(ctx) }()
	go func() { defer background.Done(); packageScheduler.Run(ctx) }()
	go func() { defer background.Done(); dockerScanScheduler.Run(ctx) }()
	go func() { defer background.Done(); dockerMetricsScheduler.Run(ctx) }()
	go func() { defer background.Done(); dockerRetentionService.Run(ctx) }()
	go func() { defer background.Done(); updateExecutionWorker.Run(ctx) }()
	go func() { defer background.Done(); rebootExecutionWorker.Run(ctx) }()
	go func() { defer background.Done(); databaseMetricsScheduler.Run(ctx) }()
	go func() { defer background.Done(); databaseRetentionService.Run(ctx) }()
	go func() { defer background.Done(); databaseDeepMetricsScheduler.Run(ctx) }()
	go func() { defer background.Done(); databaseOperationWorker.Run(ctx) }()
	go func() { defer background.Done(); alertEngine.Run(ctx, cfg.AlertEvalInterval) }()
	go func() { defer background.Done(); alertRetentionService.Run(ctx) }()
	go func() { defer background.Done(); objectStorageMetricsScheduler.Run(ctx) }()
	go func() { defer background.Done(); objectStorageRetentionService.Run(ctx) }()
	go func() { defer background.Done(); objectStorageDeepMetricsScheduler.Run(ctx) }()
	go func() { defer background.Done(); k8sScanScheduler.Run(ctx) }()
	go func() { defer background.Done(); dockerLogCaptureScheduler.Run(ctx) }()
	go func() { defer background.Done(); dockerLogRetentionService.Run(ctx) }()
	go func() { defer background.Done(); k8sLogCaptureScheduler.Run(ctx) }()
	go func() { defer background.Done(); k8sLogRetentionService.Run(ctx) }()
	go func() { defer background.Done(); dockerHostLogCaptureScheduler.Run(ctx) }()
	go func() { defer background.Done(); dockerHostLogRetentionService.Run(ctx) }()
	defer background.Wait()

	handler := server.NewRouter(server.Dependencies{
		Pool:                           pool,
		Store:                          store,
		Tokens:                         tokens,
		Auth:                           authService,
		OAuthRedirectBaseURL:           cfg.OAuthRedirectBaseURL,
		AppBaseURL:                     cfg.AppBaseURL,
		Authz:                          authz,
		Audit:                          audit,
		Workspaces:                     workspaceService,
		Resources:                      resourceService,
		VMs:                            vmService,
		Access:                         accessService,
		SSHKeyCredentials:              sshKeyCredentialService,
		HostKeys:                       hostKeyService,
		SSH:                            sshService,
		Discovery:                      discoveryService,
		SSHConnectTimeout:              cfg.SSHConnectTimeout,
		MonitorScheduler:               monitorScheduler,
		MonitorStaleAfter:              cfg.VMMonitorStaleAfter,
		Packages:                       packageService,
		PackageScheduler:               packageScheduler,
		ExternalPackages:               externalPackageScanner,
		SMTPTimeout:                    cfg.SMTPTimeout,
		DockerScheduler:                dockerScanScheduler,
		DockerMetricsCache:             dockerMetricsCache,
		DockerStaleAfter:               cfg.DockerMetricsStaleAfter,
		DockerStreamInterval:           cfg.DockerStatsStreamInterval,
		DockerAccess:                   dockerAccessService,
		MonitoringFolders:              monitoringFolderService,
		MonitoringDashboards:           monitoringDashboardService,
		K8sClusters:                    k8sClusterService,
		K8sAgentHub:                    k8sAgentHub,
		K8sAgentTokens:                 k8sAgentTokenService,
		K8s:                            k8sService,
		K8sScheduler:                   k8sScanScheduler,
		K8sAgentBackendURL:             cfg.K8sAgentBackendURL,
		DockerAgentHub:                 dockerAgentHub,
		DockerAgentTokens:              dockerAgentTokenService,
		DockerAgent:                    dockerAgentService,
		DockerAgentInstall:             dockerAgentInstallService,
		VMAgentHub:                     vmAgentHub,
		VMAgentTokens:                  vmAgentTokenService,
		VMAgent:                        vmAgentService,
		VMAgentInstall:                 vmAgentInstallService,
		DockerHosts:                    dockerHostService,
		DockerHostAgentTokens:          dockerHostAgentTokenService,
		DockerLogRetention:             dockerLogRetention,
		K8sLogRetention:                k8sLogRetention,
		UpdatePlans:                    updatePlanService,
		OSUpdates:                      osUpdateService,
		UpdateExecution:                updateExecutionService,
		UpdateWorker:                   updateExecutionWorker,
		RebootExecution:                rebootExecutionService,
		RebootWorker:                   rebootExecutionWorker,
		Databases:                      databaseService,
		DatabaseMetricsScheduler:       databaseMetricsScheduler,
		DatabaseDeepMetricsScheduler:   databaseDeepMetricsScheduler,
		DatabaseCredentials:            databaseCredentialService,
		DatabaseMetricsCache:           databaseMetricsCache,
		DatabaseDeepMetricsCache:       databaseDeepMetricsCache,
		DatabaseFastThresholds:         databaseHealthThresholds,
		DatabasePerfThresholds:         databasePerformanceThresholds,
		DatabaseStaleAfter:             cfg.DatabaseMetricsStaleAfter,
		DatabaseStreamInterval:         cfg.DatabaseMetricsInterval,
		DatabaseConnectTimeout:         cfg.DatabaseConnectionTimeout,
		DatabaseCommandTimeout:         cfg.DatabaseQueryTimeout,
		DatabaseBrowser:                databaseBrowserService,
		DatabaseConnectionLimiter:      databaseConnectionLimiter,
		DatabaseOperations:             databaseOperationService,
		DatabaseOperationWorker:        databaseOperationWorker,
		Alerts:                         alertService,
		AlertRules:                     alertRuleService,
		NotificationPolicies:           notificationPolicyService,
		Notifications:                  notificationService,
		AlertStreamInterval:            cfg.AlertStreamInterval,
		ObjectStorages:                 objectStorageService,
		ObjectStorageCredentials:       objectStorageCredentialService,
		ObjectStorageMetricsCache:      objectStorageMetricsCache,
		ObjectStorageConnectionTimeout: cfg.ObjectStorageConnectionTimeout,
		ObjectStorageBrowser:           objectStorageBrowserService,
		ObjectStorageMaxPageSize:       cfg.ObjectStorageMaxPageSize,
		ObjectStoragePreviewMaxBytes:   cfg.ObjectStoragePreviewMaxBytes,
		ObjectStorageDownloadURLTTL:    cfg.ObjectStorageDownloadURLTTL,
		CookieSecure:                   cfg.CookieSecure,
		FrontendOrigin:                 cfg.FrontendOrigin,
		ProxyKey:                       cfg.ProxyKey,
		MaxRequestBodyBytes:            cfg.MaxRequestBodyBytes,
		LoginRateLimitAttempts:         cfg.LoginRateLimitAttempts,
		LoginRateLimitWindow:           cfg.LoginRateLimitWindow,
		AuditQuery:                     auditQueryService,
		UserPreferences:                userPreferencesService,
		PlatformConfig:                 platformConfigView,
		PlatformSettings:               platformSettingsService,
		Logger:                         logger,
	})

	// WriteTimeout must comfortably exceed the slowest possible request.
	// Discovery runs up to 8 sequential SSH commands after connecting
	// (worst case: SSHConnectTimeout + 8*SSHCommandTimeout); 10s (the old
	// fixed value) was actually *shorter than or equal to* SSHConnectTimeout
	// alone, so net/http was closing the connection out from under handlers
	// that were about to write a perfectly good response -- the client saw
	// an empty reply while the server's own access log showed 200. A manual
	// package scan (spec §29's POST .../packages/scan) can run up to 4
	// sequential package-manager commands (list installed, refresh, check-
	// update, check-update --security) at PackageScanCommandTimeout each,
	// which is now the larger worst case with its longer default timeout.
	// A manual Docker scan (spec §61's POST .../docker/scan) can run up to
	// 10 sequential commands after connecting: command -v docker, docker
	// version, docker info, docker ps -aq + docker inspect, docker images,
	// docker network ls -q + docker network inspect, docker volume ls -q +
	// docker volume inspect -- each at PackageScanCommandTimeout (the
	// discovery DockerClient's configured timeout, chosen for its slower
	// batched-inspect commands).
	// POST /api/vms/:id/updates/refresh (spec §48) runs a full package
	// scan followed by a full OS-update scan in the same request -- the
	// OS-update half is its own SSH connection with up to ~7 sequential
	// commands (os-release, uname -r, do-release-upgrade existence+check,
	// reboot-required existence+check) at SSHCommandTimeout each.
	sshWorstCase := cfg.SSHConnectTimeout + 8*cfg.SSHCommandTimeout
	packageWorstCase := cfg.SSHConnectTimeout + 4*cfg.PackageScanCommandTimeout
	dockerWorstCase := cfg.SSHConnectTimeout + 10*cfg.PackageScanCommandTimeout
	updateRefreshWorstCase := packageWorstCase + cfg.SSHConnectTimeout + 7*cfg.SSHCommandTimeout
	worstCase := sshWorstCase
	if packageWorstCase > worstCase {
		worstCase = packageWorstCase
	}
	if dockerWorstCase > worstCase {
		worstCase = dockerWorstCase
	}
	if updateRefreshWorstCase > worstCase {
		worstCase = updateRefreshWorstCase
	}
	writeTimeout := worstCase + 30*time.Second

	srv := &http.Server{
		Addr:         ":" + cfg.AppPort,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: writeTimeout,
		IdleTimeout:  60 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("server starting", "port", cfg.AppPort, "env", cfg.AppEnv)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}

	logger.Info("server stopped gracefully")
	return nil
}
