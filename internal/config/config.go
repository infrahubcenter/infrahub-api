// Package config loads application configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime configuration for the server.
type Config struct {
	AppEnv      string
	AppPort     string
	DatabaseURL string
	JWTSecret   string

	DBMaxConns       int32
	DBMinConns       int32
	DBConnectTimeout time.Duration

	FrontendOrigin string
	// ProxyKey (INFRAHUB_PROXY_KEY): when set, only requests carrying it in
	// X-Infrahub-Proxy-Key (plus WebSocket upgrades and health checks) are
	// served -- see middleware.RequireProxyKey.
	ProxyKey string
	// LicenseKey (INFRAHUB_LICENSE_KEY): a signed Infra Hub Center license
	// for a paid plan; empty means the free Community plan -- see
	// services.ParseLicense.
	LicenseKey      string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	// CookieSecure controls the Secure flag on auth cookies. It defaults to
	// true unless APP_ENV is "development", so local HTTP development works
	// without HTTPS while any non-development deployment is secure by
	// default; COOKIE_SECURE can still override either way.
	CookieSecure bool

	BootstrapAdminEmail    string
	BootstrapAdminName     string
	BootstrapAdminPassword string

	// SSHCredentialEncryptionKey is a base64-encoded 32-byte AES-256 key
	// (see `go run ./cmd/gen-encryption-key`). It never lives in
	// PostgreSQL and must never be committed to git.
	SSHCredentialEncryptionKey string
	SSHConnectTimeout          time.Duration
	SSHCommandTimeout          time.Duration

	// VM monitoring (Step 6). None of these are hardcoded elsewhere in the
	// application -- see docs/vm-monitoring.md.
	VMMonitorInterval       time.Duration
	VMMonitorWorkers        int32
	VMMonitorStaleAfter     time.Duration
	VMMonitorRetentionDays  int32
	VMCPUWarningPercent     float64
	VMCPUCriticalPercent    float64
	VMMemoryWarningPercent  float64
	VMMemoryCriticalPercent float64
	VMDiskWarningPercent    float64
	VMDiskCriticalPercent   float64

	// Linux package discovery/update detection (Step 7). See
	// docs/package-management.md.
	PackageScanInterval       time.Duration
	PackageScanWorkers        int32
	PackageScanCommandTimeout time.Duration

	// Docker discovery/inventory/metrics (Step 8). See
	// docs/docker-monitoring.md. Deliberately three independent cadences,
	// never combined: DockerScanInterval (inventory, slow) is unrelated to
	// DockerMetricsInterval (container stats collection, fast), which is
	// itself unrelated to DockerStatsStreamInterval (the WebSocket push
	// cadence, which never triggers its own collection).
	DockerScanInterval         time.Duration
	DockerScanWorkers          int32
	DockerMetricsInterval      time.Duration
	DockerMetricsWorkers       int32
	DockerStatsStreamInterval  time.Duration
	DockerMetricsRetentionDays int32
	DockerMetricsStaleAfter    time.Duration

	// Update Center (Step 9). See docs/update-center.md. No cadence of its
	// own -- OS/kernel/reboot detection rides on Step 7's existing
	// PackageScanInterval/PackageScanWorkers (spec §67: "do not create
	// another independent package scan scheduler just for Update Center").
	UpdateMetadataStaleAfter time.Duration

	// Update execution engine (Step 10). See docs/update-execution.md.
	// UpdateCommandTimeout is deliberately much longer than
	// SSHCommandTimeout above -- package installs can legitimately take
	// minutes, unlike the fixed, fast, read-only discovery commands.
	UpdateWorkers            int32
	MaxConcurrentUpdates     int32
	MaxPackagesPerUpdatePlan int32
	UpdateCommandTimeout     time.Duration
	UpdateLogMaxBytes        int64

	// Controlled VM reboot (Step 11). See docs/vm-reboot.md.
	// MaxConcurrentVMOperations is a NEW, shared cap spanning both the
	// reboot worker and (eventually) other operation types -- deliberately
	// separate from MaxConcurrentUpdates, which continues to gate only
	// the update-execution worker's own semaphore unchanged from Step 10.
	RebootWorkers              int32
	MaxConcurrentVMOperations  int32
	RebootTimeout              time.Duration
	RebootInitialWait          time.Duration
	RebootMaxReconnectAttempts int32

	// Database discovery/monitoring (Step 12, read-only). See
	// docs/database-monitoring.md. Discovery and metrics are
	// deliberately separate cadences (spec #78), same as Docker's own
	// Step 8 split.
	DatabaseDiscoveryInterval     time.Duration
	DatabaseDiscoveryWorkers      int32
	DatabaseMetricsInterval       time.Duration
	DatabaseMetricsWorkers        int32
	DatabaseMetricsRetentionDays  int32
	DatabaseMetricsStaleAfter     time.Duration
	DatabaseConnectionWarningPct  float64
	DatabaseConnectionCriticalPct float64
	DatabaseMemoryWarningPct      float64
	DatabaseMemoryCriticalPct     float64
	DatabaseConnectionTimeout     time.Duration
	DatabaseQueryTimeout          time.Duration

	// Advanced database performance monitoring (Step 13, still read-only).
	// See docs/database-performance.md. Deep metrics run on their own,
	// much less frequent cadence (spec #76/#77) so an expensive query
	// ranking/lock/replication collection can never delay the cheap, fast
	// common-metrics cycle Step 12 already established.
	DatabaseSlowQueryMs               int32
	DatabaseLongRunningQuerySeconds   int32
	DatabaseQueryMetricsRetentionDays int32
	DatabaseDeepMetricsInterval       time.Duration
	DatabaseDeepMetricsWorkers        int32
	DatabaseMonitorMaxConnections     int32
	DatabaseQueryTextCapture          bool
	DatabaseQueryTextMaxBytes         int32
	DatabaseCacheHitWarningPct        float64
	DatabaseCacheHitCriticalPct       float64
	DatabaseLockWarningCount          int32
	DatabaseAlertCooldown             time.Duration
	DatabaseGrowthWarningPercent      float64

	// Controlled database operations + admin remediation (Step 14). See
	// docs/database-operations.md. MaxConcurrentDatabaseOperations is a
	// new, dedicated cap -- deliberately separate from
	// MaxConcurrentVMOperations/MaxConcurrentUpdates, since a database
	// operation's worker pool is entirely independent of the VM-side ones.
	DatabaseOperationWorkers        int32
	MaxConcurrentDatabaseOperations int32
	DatabaseOperationTimeout        time.Duration
	DatabaseOperationLogMaxBytes    int64

	// Standalone object storage monitoring (Step 17). Phase 1 added
	// ObjectStorageConnectionTimeout (used for both the connect and command
	// phase of a HeadBucket probe). Phase 2 (fast metrics scheduler) added
	// the fast-cycle block, mirroring the Database* fast-cycle fields above.
	// Phase 3 (deep metrics: security facts, growth, alerts,
	// recommendations) adds the rest of this block below, mirroring the
	// Database* deep-cycle/threshold fields.
	ObjectStorageConnectionTimeout     time.Duration
	ObjectStorageMetricsInterval       time.Duration
	ObjectStorageMetricsWorkers        int32
	ObjectStorageMetricsRetentionDays  int32
	ObjectStorageMetricsStaleAfter     time.Duration
	ObjectStorageMonitorMaxConnections int32

	// Deep metrics cadence: its own, much less frequent interval/worker
	// pool, same rationale as DatabaseDeepMetricsInterval/Workers -- an
	// expensive CloudWatch/bucket-config/bounded-listing cycle must never
	// delay or starve the cheap fast (HeadBucket-only) cycle above.
	ObjectStorageDeepMetricsInterval time.Duration
	ObjectStorageDeepMetricsWorkers  int32
	// ObjectStorageGrowthWarningPercent/ObjectStorageErrorRateWarningPercent
	// mirror DatabaseGrowthWarningPercent's role: the projected-growth-over-
	// 7-days / observed-error-rate percentage above which
	// OBJECT_STORAGE_HIGH_GROWTH/OBJECT_STORAGE_HIGH_ERROR_RATE
	// recommendations fire.
	ObjectStorageGrowthWarningPercent    float64
	ObjectStorageErrorRateWarningPercent float64
	// ObjectStoragePublicAccessSeverity resolves spec's "WARNING or CRITICAL
	// per configured policy" for a publicly-accessible bucket (plan decision
	// #4: no per-admin severity-policy mechanism exists anywhere in this
	// codebase yet, so this is a single global config default, consistent
	// with every other recommendation's hardcoded severity today).
	ObjectStoragePublicAccessSeverity string

	// Object storage browser (Step 17 Phase 4): read-only object
	// listing/prefix navigation/metadata/short-lived-URL download/text-
	// JSON preview -- no write/delete/upload S3 call exists anywhere in
	// this feature. ObjectStorageMaxPageSize is the server-enforced upper
	// bound on GET .../objects and .../objects/search's page size
	// regardless of what the client requests (mirrors
	// MaxBrowserRowLimit's role for the standalone database browser, just
	// config-overridable here). ObjectStorageDownloadURLTTL bounds how
	// long a GET .../objects/download presigned URL stays valid -- never a
	// permanent link. ObjectStoragePreviewMaxBytes caps how much of an
	// object GET .../objects/preview will ever read into memory; an object
	// larger than this is refused before any GetObject call is even made.
	ObjectStorageMaxPageSize     int32
	ObjectStorageDownloadURLTTL  time.Duration
	ObjectStoragePreviewMaxBytes int64

	// Central alerts + notifications (Step 16). See docs/alerts.md.
	AlertEvalInterval           time.Duration
	AlertStreamInterval         time.Duration
	AlertNotificationCooldown   time.Duration
	AlertNotificationMaxRetries int32
	AlertWebhookTimeout         time.Duration
	AlertRetentionDays          int32
	NotificationRetentionDays   int32

	// EMAIL notification delivery (services.EmailProvider). SMTPHost empty
	// means email delivery is unconfigured -- EMAIL stays a selectable
	// policy channel either way, but every send fails with a clear
	// "SMTP is not configured" error (marked FAILED, notification_service.go's
	// existing "never fabricate success" contract) rather than the backend
	// refusing to start. SMTPUseTLS selects implicit TLS (typically port
	// 465); when false, STARTTLS is used opportunistically on a plain
	// connection (typically port 587/25) if the server offers it.
	SMTPHost      string
	SMTPPort      int32
	SMTPUsername  string
	SMTPPassword  string
	SMTPFromEmail string
	SMTPUseTLS    bool
	SMTPTimeout   time.Duration

	// AppBaseURL is the frontend's own externally-reachable URL, used only
	// to build the "sign in here" link in a new user's invite email
	// (services.InviteMailer) -- unrelated to FrontendOrigin, which is a
	// WebSocket CORS check, not a link destination.
	AppBaseURL string

	// OAuth login (GitHub/Google), invite-only: signing in only succeeds
	// for an email that already has an admin-created account -- see
	// services.AuthService.LoginWithVerifiedEmail. Empty Client ID/Secret
	// means that provider is unconfigured (its button is simply not shown/
	// its /start route 404s), same "wire it now, real credentials later"
	// posture as SMTP above. OAuthRedirectBaseURL is deliberately distinct
	// from AppBaseURL: the OAuth provider redirects the browser straight
	// back to the BACKEND's own callback route (the frontend has no
	// `/api/*` proxy -- the browser calls the backend cross-origin
	// directly, see frontend/src/lib/api.ts's apiFetch), so this must be
	// this backend's own externally-reachable origin, exactly like
	// DockerAgentBackendURL below is for the same reason.
	GitHubClientID       string
	GitHubClientSecret   string
	GoogleClientID       string
	GoogleClientSecret   string
	OAuthRedirectBaseURL string

	// HTTP hardening (Step 20). MaxRequestBodyBytes bounds every request
	// body via middleware.MaxBody -- generous for this project's small,
	// well-shaped JSON payloads (nothing here accepts a file upload).
	// LoginRateLimit* bounds POST /api/auth/login attempts per source IP,
	// mitigating credential stuffing/brute force without touching normal
	// session refresh/logout traffic.
	MaxRequestBodyBytes    int64
	LoginRateLimitAttempts int32
	LoginRateLimitWindow   time.Duration

	// Standalone Kubernetes clusters (Step 25). K8sConnectTimeout bounds
	// every request through a cluster's rest.Config (discovery, list pods,
	// metrics, connection test) -- mirrors ObjectStorageConnectionTimeout's
	// single-timeout-for-everything shape, since client-go requests are all
	// comparably cheap. K8sScanInterval/Workers mirror DockerScanInterval/
	// Workers exactly (K8s pod discovery is the direct analogue of Docker
	// container discovery).
	K8sConnectTimeout time.Duration
	K8sScanInterval   time.Duration
	K8sScanWorkers    int32

	// Log history (a later addition to Step 24/25): a periodic, bounded
	// background capture keeps up to *LogRetentionDays of searchable Docker
	// container / K8s pod log history, independent of the live-tail
	// WebSockets. See services/docker_log_capture.go and
	// services/k8s_log_capture.go.
	DockerLogCaptureInterval time.Duration
	DockerLogCaptureWorkers  int32
	DockerLogRetentionDays   int32
	K8sLogCaptureInterval    time.Duration
	K8sLogCaptureWorkers     int32
	K8sLogRetentionDays      int32

	// Log archiving: an optional extra step every retention sweep above
	// (Docker/K8s/Docker Host) runs right before deleting rows older than
	// its own *LogRetentionDays window -- writes them out somewhere
	// durable first, so the retention window closing doesn't mean losing
	// them outright. Off by default (LogArchiveBackend="none"); see
	// services/log_archive.go. LogArchiveS3SecretAccessKey is the one
	// secret-shaped field here -- belongs in development.ini.enc/
	// production.ini.enc, ENC(...)-wrapped, same as every other secret.
	LogArchiveBackend           string
	LogArchiveVolumePath        string
	LogArchiveS3Bucket          string
	LogArchiveS3Region          string
	LogArchiveS3Endpoint        string
	LogArchiveS3Prefix          string
	LogArchiveS3AccessKeyID     string
	LogArchiveS3SecretAccessKey string

	// Per-VM Docker agent (Docker+Kubernetes monitoring rework, Phase 1).
	// See docker-agent/ at the repo root and services/docker_agent_*.go.
	// Unlike the Kubernetes agent (an external cluster the admin configures
	// by hand), the Docker agent's install is fully automated over the
	// VM's existing SSH access, so the backend must know its OWN
	// externally-reachable WebSocket URL to embed in the pushed agent
	// config -- there is no way to derive this reliably (proxies, Docker
	// networking, multiple interfaces), so it must be configured
	// explicitly. Left empty by default so an install attempt fails
	// fast and clearly rather than embedding a guessed/wrong URL.
	// DockerAgentCommandTimeout mirrors K8sConnectTimeout's role (bounds
	// every request/response round trip to a connected agent).
	// DockerAgentInstallTimeout bounds the whole SSH install flow (binary
	// compile is not included -- that happens once, before any SSH work).
	DockerAgentBackendURL     string
	DockerAgentCommandTimeout time.Duration
	DockerAgentInstallTimeout time.Duration

	// VMAgentBackendURL/CommandTimeout: same shape and same rationale as
	// the Docker agent fields above, for the separate push-based VM Agent
	// (migrations/052_vm_agent.sql). No InstallTimeout counterpart -- the
	// VM Agent has no SSH-based automated install to bound (see
	// services/vm_agent_install.go's doc comment).
	VMAgentBackendURL     string
	VMAgentCommandTimeout time.Duration

	// K8sAgentBackendURL: same rationale as DockerAgentBackendURL above --
	// the Kubernetes agent install is manual (the admin runs kubectl
	// themselves, see k8s-agent/deploy/manifest.yaml), but the backend
	// still needs to hand back its own externally-reachable WebSocket URL
	// so the Connect Cluster/regenerate-token screens can show a real,
	// usable backend-url instead of the browser's own (often
	// localhost-only, meaningless from inside a remote cluster) API base.
	K8sAgentBackendURL string
}

// Load reads configuration from environment variables, applying sane
// defaults for local development where possible.
func Load() (*Config, error) {
	// Loads <APP_ENV>.ini (development.ini.enc/production.ini.enc) -- see
	// encrypted_env.go's own doc comment for why this replaced a plaintext
	// .env file. Best-effort in the same spirit .env's loader always was:
	// a missing ini file is not an error, since a real deployment may set
	// every env var directly with no file at all. APP_ENV itself must
	// come from the real process environment (or default to
	// "development") to pick which file to open -- it can't live inside
	// the file being selected by its own value.
	appEnv := getEnv("APP_ENV", "development")
	if err := loadEnvFile(appEnv); err != nil {
		return nil, err
	}

	// The single source of truth for "this deployment's one externally-
	// reachable origin" -- e.g. https://your-tunnel-or-domain. When set,
	// it's the default for every other "how do I reach this backend/
	// frontend from outside" setting below, so a one-origin deployment
	// (this whole dev setup: one ngrok tunnel, one domain for frontend
	// and API alike) only needs this ONE value instead of six separate
	// URLs kept in sync by hand. Any of those six can still be set
	// explicitly to override just that one (e.g. a production deployment
	// serving its frontend and API from different hosts).
	publicURL := strings.TrimRight(os.Getenv("PUBLIC_URL"), "/")

	cfg := &Config{
		AppEnv:      appEnv,
		AppPort:     getEnv("APP_PORT", "8080"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		JWTSecret:   os.Getenv("JWT_SECRET"),

		DBMaxConns:       getEnvInt32("DB_MAX_CONNS", 10),
		DBMinConns:       getEnvInt32("DB_MIN_CONNS", 2),
		DBConnectTimeout: time.Duration(getEnvInt32("DB_CONNECT_TIMEOUT_SECONDS", 5)) * time.Second,

		FrontendOrigin:  getEnvOrPublicURL("FRONTEND_ORIGIN", publicURL, "http://localhost:3000"),
		ProxyKey:        os.Getenv("INFRAHUB_PROXY_KEY"),
		LicenseKey:      os.Getenv("INFRAHUB_LICENSE_KEY"),
		AccessTokenTTL:  time.Duration(getEnvInt32("ACCESS_TOKEN_TTL_MINUTES", 15)) * time.Minute,
		RefreshTokenTTL: time.Duration(getEnvInt32("REFRESH_TOKEN_TTL_DAYS", 7)) * 24 * time.Hour,

		BootstrapAdminEmail:    os.Getenv("BOOTSTRAP_ADMIN_EMAIL"),
		BootstrapAdminName:     os.Getenv("BOOTSTRAP_ADMIN_NAME"),
		BootstrapAdminPassword: os.Getenv("BOOTSTRAP_ADMIN_PASSWORD"),

		SSHCredentialEncryptionKey: os.Getenv("SSH_CREDENTIAL_ENCRYPTION_KEY"),
		SSHConnectTimeout:          getEnvDuration("SSH_CONNECT_TIMEOUT", 10*time.Second),
		SSHCommandTimeout:          getEnvDuration("SSH_COMMAND_TIMEOUT", 30*time.Second),

		VMMonitorInterval:       getEnvDuration("VM_MONITOR_INTERVAL", 60*time.Second),
		VMMonitorWorkers:        getEnvInt32("VM_MONITOR_WORKERS", 5),
		VMMonitorStaleAfter:     getEnvDuration("VM_MONITOR_STALE_AFTER", 5*time.Minute),
		VMMonitorRetentionDays:  getEnvInt32("VM_MONITOR_RETENTION_DAYS", 30),
		VMCPUWarningPercent:     getEnvFloat64("VM_CPU_WARNING_PERCENT", 80),
		VMCPUCriticalPercent:    getEnvFloat64("VM_CPU_CRITICAL_PERCENT", 90),
		VMMemoryWarningPercent:  getEnvFloat64("VM_MEMORY_WARNING_PERCENT", 80),
		VMMemoryCriticalPercent: getEnvFloat64("VM_MEMORY_CRITICAL_PERCENT", 90),
		VMDiskWarningPercent:    getEnvFloat64("VM_DISK_WARNING_PERCENT", 80),
		VMDiskCriticalPercent:   getEnvFloat64("VM_DISK_CRITICAL_PERCENT", 90),

		PackageScanInterval:       getEnvDuration("PACKAGE_SCAN_INTERVAL", 6*time.Hour),
		PackageScanWorkers:        getEnvInt32("PACKAGE_SCAN_WORKERS", 2),
		PackageScanCommandTimeout: getEnvDuration("PACKAGE_SCAN_COMMAND_TIMEOUT", 90*time.Second),

		DockerScanInterval:         getEnvDuration("DOCKER_SCAN_INTERVAL", 10*time.Minute),
		DockerScanWorkers:          getEnvInt32("DOCKER_SCAN_WORKERS", 2),
		DockerMetricsInterval:      getEnvDuration("DOCKER_METRICS_INTERVAL", 15*time.Second),
		DockerMetricsWorkers:       getEnvInt32("DOCKER_METRICS_WORKERS", 3),
		DockerStatsStreamInterval:  getEnvDuration("DOCKER_STATS_STREAM_INTERVAL", 1*time.Second),
		DockerMetricsRetentionDays: getEnvInt32("DOCKER_METRICS_RETENTION_DAYS", 7),
		DockerMetricsStaleAfter:    getEnvDuration("DOCKER_METRICS_STALE_AFTER", 60*time.Second),

		UpdateMetadataStaleAfter: getEnvDuration("UPDATE_METADATA_STALE_AFTER", 1*time.Hour),

		UpdateWorkers:            getEnvInt32("UPDATE_WORKERS", 2),
		MaxConcurrentUpdates:     getEnvInt32("MAX_CONCURRENT_UPDATES", 2),
		MaxPackagesPerUpdatePlan: getEnvInt32("MAX_PACKAGES_PER_UPDATE_PLAN", 100),
		UpdateCommandTimeout:     getEnvDuration("UPDATE_COMMAND_TIMEOUT", 30*time.Minute),
		UpdateLogMaxBytes:        getEnvInt64("UPDATE_LOG_MAX_BYTES", 2*1024*1024),

		RebootWorkers:              getEnvInt32("REBOOT_WORKERS", 2),
		MaxConcurrentVMOperations:  getEnvInt32("MAX_CONCURRENT_VM_OPERATIONS", 3),
		RebootTimeout:              getEnvDuration("REBOOT_TIMEOUT", 10*time.Minute),
		RebootInitialWait:          getEnvDuration("REBOOT_INITIAL_WAIT", 10*time.Second),
		RebootMaxReconnectAttempts: getEnvInt32("REBOOT_MAX_RECONNECT_ATTEMPTS", 12),

		DatabaseDiscoveryInterval:     getEnvDuration("DATABASE_DISCOVERY_INTERVAL", 10*time.Minute),
		DatabaseDiscoveryWorkers:      getEnvInt32("DATABASE_DISCOVERY_WORKERS", 2),
		DatabaseMetricsInterval:       getEnvDuration("DATABASE_METRICS_INTERVAL", 15*time.Second),
		DatabaseMetricsWorkers:        getEnvInt32("DATABASE_METRICS_WORKERS", 3),
		DatabaseMetricsRetentionDays:  getEnvInt32("DATABASE_METRICS_RETENTION_DAYS", 7),
		DatabaseMetricsStaleAfter:     getEnvDuration("DATABASE_METRICS_STALE_AFTER", 60*time.Second),
		DatabaseConnectionWarningPct:  getEnvFloat64("DATABASE_CONNECTION_WARNING_PERCENT", 80),
		DatabaseConnectionCriticalPct: getEnvFloat64("DATABASE_CONNECTION_CRITICAL_PERCENT", 95),
		DatabaseMemoryWarningPct:      getEnvFloat64("DATABASE_MEMORY_WARNING_PERCENT", 80),
		DatabaseMemoryCriticalPct:     getEnvFloat64("DATABASE_MEMORY_CRITICAL_PERCENT", 95),
		DatabaseConnectionTimeout:     getEnvDuration("DATABASE_CONNECTION_TIMEOUT", 10*time.Second),
		DatabaseQueryTimeout:          getEnvDuration("DATABASE_QUERY_TIMEOUT", 5*time.Second),

		DatabaseSlowQueryMs:               getEnvInt32("DATABASE_SLOW_QUERY_MS", 1000),
		DatabaseLongRunningQuerySeconds:   getEnvInt32("DATABASE_LONG_RUNNING_QUERY_SECONDS", 60),
		DatabaseQueryMetricsRetentionDays: getEnvInt32("DATABASE_QUERY_METRICS_RETENTION_DAYS", 7),
		DatabaseDeepMetricsInterval:       getEnvDuration("DATABASE_DEEP_METRICS_INTERVAL", 60*time.Second),
		DatabaseDeepMetricsWorkers:        getEnvInt32("DATABASE_DEEP_METRICS_WORKERS", 2),
		DatabaseMonitorMaxConnections:     getEnvInt32("DATABASE_MONITOR_MAX_CONNECTIONS", 3),
		DatabaseQueryTextCapture:          getEnvBool("DATABASE_QUERY_TEXT_CAPTURE", false),
		DatabaseQueryTextMaxBytes:         getEnvInt32("DATABASE_QUERY_TEXT_MAX_BYTES", 4096),
		DatabaseCacheHitWarningPct:        getEnvFloat64("DATABASE_CACHE_HIT_WARNING_PERCENT", 95),
		DatabaseCacheHitCriticalPct:       getEnvFloat64("DATABASE_CACHE_HIT_CRITICAL_PERCENT", 90),
		DatabaseLockWarningCount:          getEnvInt32("DATABASE_LOCK_WARNING_COUNT", 3),
		DatabaseAlertCooldown:             getEnvDuration("DATABASE_ALERT_COOLDOWN", 15*time.Minute),
		DatabaseGrowthWarningPercent:      getEnvFloat64("DATABASE_GROWTH_WARNING_PERCENT", 20),

		DatabaseOperationWorkers:        getEnvInt32("DATABASE_OPERATION_WORKERS", 2),
		MaxConcurrentDatabaseOperations: getEnvInt32("MAX_CONCURRENT_DATABASE_OPERATIONS", 3),
		DatabaseOperationTimeout:        getEnvDuration("DATABASE_OPERATION_TIMEOUT", 300*time.Second),
		DatabaseOperationLogMaxBytes:    getEnvInt64("DATABASE_OPERATION_LOG_MAX_BYTES", 1*1024*1024),

		ObjectStorageConnectionTimeout:     getEnvDuration("OBJECT_STORAGE_CONNECTION_TIMEOUT", 10*time.Second),
		ObjectStorageMetricsInterval:       getEnvDuration("OBJECT_STORAGE_METRICS_INTERVAL", 60*time.Second),
		ObjectStorageMetricsWorkers:        getEnvInt32("OBJECT_STORAGE_METRICS_WORKERS", 3),
		ObjectStorageMetricsRetentionDays:  getEnvInt32("OBJECT_STORAGE_METRICS_RETENTION_DAYS", 30),
		ObjectStorageMetricsStaleAfter:     getEnvDuration("OBJECT_STORAGE_METRICS_STALE_AFTER", 5*time.Minute),
		ObjectStorageMonitorMaxConnections: getEnvInt32("OBJECT_STORAGE_MONITOR_MAX_CONNECTIONS", 5),

		ObjectStorageDeepMetricsInterval:     getEnvDuration("OBJECT_STORAGE_DEEP_METRICS_INTERVAL", 5*time.Minute),
		ObjectStorageDeepMetricsWorkers:      getEnvInt32("OBJECT_STORAGE_DEEP_METRICS_WORKERS", 2),
		ObjectStorageGrowthWarningPercent:    getEnvFloat64("OBJECT_STORAGE_GROWTH_WARNING_PERCENT", 20),
		ObjectStorageErrorRateWarningPercent: getEnvFloat64("OBJECT_STORAGE_ERROR_RATE_WARNING_PERCENT", 5),
		ObjectStoragePublicAccessSeverity:    getEnv("OBJECT_STORAGE_PUBLIC_ACCESS_SEVERITY", "CRITICAL"),

		ObjectStorageMaxPageSize:     getEnvInt32("OBJECT_STORAGE_MAX_PAGE_SIZE", 200),
		ObjectStorageDownloadURLTTL:  getEnvDuration("OBJECT_STORAGE_DOWNLOAD_URL_TTL", 5*time.Minute),
		ObjectStoragePreviewMaxBytes: getEnvInt64("OBJECT_STORAGE_PREVIEW_MAX_BYTES", 5*1024*1024),

		AlertEvalInterval:           getEnvDuration("ALERT_EVAL_INTERVAL", 30*time.Second),
		AlertStreamInterval:         getEnvDuration("ALERT_STREAM_INTERVAL", 15*time.Second),
		AlertNotificationCooldown:   getEnvDuration("ALERT_NOTIFICATION_COOLDOWN", 15*time.Minute),
		AlertNotificationMaxRetries: getEnvInt32("ALERT_NOTIFICATION_MAX_RETRIES", 3),
		AlertWebhookTimeout:         getEnvDuration("ALERT_WEBHOOK_TIMEOUT", 10*time.Second),
		AlertRetentionDays:          getEnvInt32("ALERT_RETENTION_DAYS", 90),
		NotificationRetentionDays:   getEnvInt32("NOTIFICATION_RETENTION_DAYS", 90),

		MaxRequestBodyBytes:    getEnvInt64("MAX_REQUEST_BODY_BYTES", 2*1024*1024),
		LoginRateLimitAttempts: getEnvInt32("LOGIN_RATE_LIMIT_ATTEMPTS", 10),
		LoginRateLimitWindow:   getEnvDuration("LOGIN_RATE_LIMIT_WINDOW", 5*time.Minute),

		K8sConnectTimeout: getEnvDuration("K8S_CONNECT_TIMEOUT", 10*time.Second),
		K8sScanInterval:   getEnvDuration("K8S_SCAN_INTERVAL", 10*time.Minute),
		K8sScanWorkers:    getEnvInt32("K8S_SCAN_WORKERS", 2),

		DockerLogCaptureInterval: getEnvDuration("DOCKER_LOG_CAPTURE_INTERVAL", 30*time.Second),
		DockerLogCaptureWorkers:  getEnvInt32("DOCKER_LOG_CAPTURE_WORKERS", 3),
		DockerLogRetentionDays:   getEnvInt32("DOCKER_LOG_RETENTION_DAYS", 30),
		K8sLogCaptureInterval:    getEnvDuration("K8S_LOG_CAPTURE_INTERVAL", 30*time.Second),
		K8sLogCaptureWorkers:     getEnvInt32("K8S_LOG_CAPTURE_WORKERS", 3),
		K8sLogRetentionDays:      getEnvInt32("K8S_LOG_RETENTION_DAYS", 30),

		LogArchiveBackend:           getEnv("LOG_ARCHIVE_BACKEND", "none"),
		LogArchiveVolumePath:        getEnv("LOG_ARCHIVE_VOLUME_PATH", "./log-archive"),
		LogArchiveS3Bucket:          os.Getenv("LOG_ARCHIVE_S3_BUCKET"),
		LogArchiveS3Region:          os.Getenv("LOG_ARCHIVE_S3_REGION"),
		LogArchiveS3Endpoint:        os.Getenv("LOG_ARCHIVE_S3_ENDPOINT"),
		LogArchiveS3Prefix:          os.Getenv("LOG_ARCHIVE_S3_PREFIX"),
		LogArchiveS3AccessKeyID:     os.Getenv("LOG_ARCHIVE_S3_ACCESS_KEY_ID"),
		LogArchiveS3SecretAccessKey: os.Getenv("LOG_ARCHIVE_S3_SECRET_ACCESS_KEY"),

		DockerAgentBackendURL:     getAgentURLOrPublicURL("DOCKER_AGENT_BACKEND_URL", publicURL, "/api/docker-agent/connect"),
		DockerAgentCommandTimeout: getEnvDuration("DOCKER_AGENT_COMMAND_TIMEOUT", 10*time.Second),
		DockerAgentInstallTimeout: getEnvDuration("DOCKER_AGENT_INSTALL_TIMEOUT", 2*time.Minute),

		VMAgentBackendURL:     getAgentURLOrPublicURL("VM_AGENT_BACKEND_URL", publicURL, "/api/vm-agent/connect"),
		VMAgentCommandTimeout: getEnvDuration("VM_AGENT_COMMAND_TIMEOUT", 10*time.Second),

		K8sAgentBackendURL: getAgentURLOrPublicURL("K8S_AGENT_BACKEND_URL", publicURL, "/api/k8s/agent/connect"),

		SMTPHost:      os.Getenv("SMTP_HOST"),
		SMTPPort:      getEnvInt32("SMTP_PORT", 587),
		SMTPUsername:  os.Getenv("SMTP_USERNAME"),
		SMTPPassword:  os.Getenv("SMTP_PASSWORD"),
		SMTPFromEmail: getEnv("SMTP_FROM_EMAIL", "notifications@infrahub.local"),
		SMTPUseTLS:    getEnvBool("SMTP_USE_TLS", false),
		SMTPTimeout:   getEnvDuration("SMTP_TIMEOUT", 10*time.Second),

		AppBaseURL: getEnvOrPublicURL("APP_BASE_URL", publicURL, "http://localhost:3000"),

		GitHubClientID:       os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret:   os.Getenv("GITHUB_CLIENT_SECRET"),
		GoogleClientID:       os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret:   os.Getenv("GOOGLE_CLIENT_SECRET"),
		OAuthRedirectBaseURL: getEnvOrPublicURL("OAUTH_REDIRECT_BASE_URL", publicURL, "http://localhost:8080"),
	}

	appEnvDefaultSecure := cfg.AppEnv != "development"
	cfg.CookieSecure = getEnvBool("COOKIE_SECURE", appEnvDefaultSecure)

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}
	if cfg.SSHCredentialEncryptionKey == "" {
		return nil, fmt.Errorf("SSH_CREDENTIAL_ENCRYPTION_KEY is required (run: go run ./cmd/gen-encryption-key)")
	}

	return cfg, nil
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getEnvOrPublicURL is getEnv's counterpart for the six "how do I reach
// this backend/frontend from outside" settings (FrontendOrigin,
// AppBaseURL, OAuthRedirectBaseURL, and the three agent connect URLs
// below): key wins if explicitly set (so any of the six can still be
// overridden individually -- e.g. a production deployment serving its
// API from a different host than its frontend), otherwise PUBLIC_URL is
// used if set, otherwise fallback. This is what lets a single-origin
// deployment (one tunnel, one domain -- true for this whole dev setup)
// configure just PUBLIC_URL once instead of keeping six copies of the
// same URL in sync by hand.
func getEnvOrPublicURL(key, publicURL, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	if publicURL != "" {
		return publicURL
	}
	return fallback
}

// getAgentURLOrPublicURL is getEnvOrPublicURL's counterpart for the three
// agent WebSocket connect URLs, which need a ws(s):// scheme and a fixed
// path appended rather than the bare origin. Empty PUBLIC_URL (and no
// explicit override) means "no default" -- these three have never had one,
// since an agent install command with no backend URL is a clear, loud
// failure rather than a silently-wrong "localhost" baked into a token a
// remote agent could never actually reach.
func getAgentURLOrPublicURL(key, publicURL, path string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	if publicURL == "" {
		return ""
	}
	wsURL := strings.Replace(publicURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	return strings.TrimRight(wsURL, "/") + path
}

func getEnvInt32(key string, fallback int32) int32 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return fallback
	}
	return int32(parsed)
}

func getEnvInt64(key string, fallback int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvFloat64(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return parsed
}
