package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// Audit action names. Never log passwords, JWTs, refresh tokens, SSH keys,
// or database/S3 credentials in Metadata.
const (
	AuditUserLoginSuccess    = "USER_LOGIN_SUCCESS"
	AuditUserLoginFailed     = "USER_LOGIN_FAILED"
	AuditUserLogout          = "USER_LOGOUT"
	AuditUserCreated         = "USER_CREATED"
	AuditUserDisabled        = "USER_DISABLED"
	AuditUserEnabled         = "USER_ENABLED"
	AuditUserDeleted         = "USER_DELETED"
	AuditUserRoleChanged     = "ROLE_CHANGED"
	AuditVMAccessGranted     = "VM_ACCESS_GRANTED"
	AuditVMAccessRevoked     = "VM_ACCESS_REVOKED"
	AuditGroupMemberAdded    = "GROUP_MEMBER_ADDED"
	AuditGroupMemberRemoved  = "GROUP_MEMBER_REMOVED"
	AuditUnauthorizedAttempt = "UNAUTHORIZED_ACCESS_ATTEMPT"

	AuditProjectCreated     = "PROJECT_CREATED"
	AuditProjectUpdated     = "PROJECT_UPDATED"
	AuditProjectDeactivated = "PROJECT_DEACTIVATED"
	AuditProjectDeleted     = "PROJECT_DELETED"

	AuditGroupCreated     = "GROUP_CREATED"
	AuditGroupUpdated     = "GROUP_UPDATED"
	AuditGroupDeactivated = "GROUP_DEACTIVATED"
	AuditGroupDeleted     = "GROUP_DELETED"

	// Workspace replaces the Project/Group tier entirely (migration
	// 043_workspaces.sql) -- the constants above are kept, unused, only so
	// old audit rows still render correctly.
	AuditWorkspaceCreated       = "WORKSPACE_CREATED"
	AuditWorkspaceUpdated       = "WORKSPACE_UPDATED"
	AuditWorkspaceDeactivated   = "WORKSPACE_DEACTIVATED"
	AuditWorkspaceDeleted       = "WORKSPACE_DELETED"
	AuditWorkspaceMemberAdded   = "WORKSPACE_MEMBER_ADDED"
	AuditWorkspaceMemberRemoved = "WORKSPACE_MEMBER_REMOVED"

	AuditVMCreated     = "VM_CREATED"
	AuditVMUpdated     = "VM_UPDATED"
	AuditVMDeactivated = "VM_DEACTIVATED"
	AuditVMDeleted     = "VM_DELETED"

	// Named, reusable SSH key credentials (ssh_key_credentials.go) -- the
	// replacement for the AuditSSHCredential* block below, which stays
	// defined-but-unused only so old audit rows still render correctly.
	AuditSSHKeyCredentialCreated = "SSH_KEY_CREDENTIAL_CREATED"
	AuditSSHKeyCredentialRenamed = "SSH_KEY_CREDENTIAL_RENAMED"
	AuditSSHKeyCredentialDeleted = "SSH_KEY_CREDENTIAL_DELETED"
	AuditVMSSHKeyAttached        = "VM_SSH_KEY_ATTACHED"
	AuditVMSSHKeyDetached        = "VM_SSH_KEY_DETACHED"

	// Step 22: VM Console. Deliberately just open/close -- never a per-
	// keystroke or per-output-chunk event, and terminal content is never
	// written to Metadata (spec: "Do NOT record every command typed. Do
	// NOT store terminal output in audit logs.").
	AuditVMConsoleOpened = "VM_CONSOLE_OPENED"
	AuditVMConsoleClosed = "VM_CONSOLE_CLOSED"

	// VM Agent (push-based metrics/logs, alongside the existing SSH
	// scheduler -- see migrations/052_vm_agent.sql). Logs open/close
	// mirror VM Console's discipline exactly: never log content itself.
	AuditVMAgentInstalled  = "VM_AGENT_INSTALLED"
	AuditVMAgentLogsOpened = "VM_AGENT_LOGS_OPENED"
	AuditVMAgentLogsClosed = "VM_AGENT_LOGS_CLOSED"

	// Kept, unused, only so old audit rows (from before named SSH key
	// credentials existed) still render correctly.
	AuditSSHCredentialConfigured = "SSH_CREDENTIAL_CONFIGURED"
	AuditSSHCredentialReplaced   = "SSH_CREDENTIAL_REPLACED"
	AuditSSHCredentialRemoved    = "SSH_CREDENTIAL_REMOVED"
	AuditSSHConnectionTest       = "SSH_CONNECTION_TEST"
	AuditSSHConnectionFailed     = "SSH_CONNECTION_FAILED"
	AuditSSHHostKeyTrusted       = "SSH_HOST_KEY_TRUSTED"
	AuditSSHHostKeyChanged       = "SSH_HOST_KEY_CHANGED"
	AuditVMDiscoveryStarted      = "VM_DISCOVERY_STARTED"
	AuditVMDiscoveryCompleted    = "VM_DISCOVERY_COMPLETED"
	AuditVMDiscoveryFailed       = "VM_DISCOVERY_FAILED"

	AuditMonitoringCollectTriggered = "MONITORING_COLLECT_TRIGGERED"

	AuditPackageScanStarted                = "PACKAGE_SCAN_STARTED"
	AuditPackageScanCompleted              = "PACKAGE_SCAN_COMPLETED"
	AuditPackageScanFailed                 = "PACKAGE_SCAN_FAILED"
	AuditPackageMetadataRefreshed          = "PACKAGE_METADATA_REFRESHED"
	AuditPackageRecommendationAcknowledged = "PACKAGE_RECOMMENDATION_ACKNOWLEDGED"
	AuditPackageRecommendationDismissed    = "PACKAGE_RECOMMENDATION_DISMISSED"
	AuditPackageBaselineReset              = "PACKAGE_BASELINE_RESET"
	AuditExternalPackageScanStarted        = "EXTERNAL_PACKAGE_SCAN_STARTED"
	AuditExternalPackageScanCompleted      = "EXTERNAL_PACKAGE_SCAN_COMPLETED"
	AuditExternalPackageScanFailed         = "EXTERNAL_PACKAGE_SCAN_FAILED"

	AuditDockerScanStarted   = "DOCKER_SCAN_STARTED"
	AuditDockerScanCompleted = "DOCKER_SCAN_COMPLETED"
	AuditDockerScanFailed    = "DOCKER_SCAN_FAILED"

	// Step 24: docker_access_grants (Project/Group-scoped view access to
	// the new Docker Monitoring/Logs section). Step 25 reuses the same
	// grants table for K8s permissions but logs those under their own
	// K8S_ACCESS_* actions (see docker_access.go handler's Grant/Revoke)
	// so the audit trail still distinguishes which feature area a grant
	// applies to.
	AuditDockerAccessGranted = "DOCKER_ACCESS_GRANTED"
	AuditDockerAccessRevoked = "DOCKER_ACCESS_REVOKED"
	AuditK8sAccessGranted    = "K8S_ACCESS_GRANTED"
	AuditK8sAccessRevoked    = "K8S_ACCESS_REVOKED"
	// Log streaming: open/close only, exactly like VM Console -- never a
	// per-line event, and log content is never written to Metadata.
	AuditDockerLogsOpened = "DOCKER_LOGS_OPENED"
	AuditDockerLogsClosed = "DOCKER_LOGS_CLOSED"

	AuditUpdateScanStarted   = "UPDATE_SCAN_STARTED"
	AuditUpdateScanCompleted = "UPDATE_SCAN_COMPLETED"
	AuditUpdateScanFailed    = "UPDATE_SCAN_FAILED"

	AuditUpdatePlanCreated   = "UPDATE_PLAN_CREATED"
	AuditUpdatePlanValidated = "UPDATE_PLAN_VALIDATED"
	AuditUpdatePlanApproved  = "UPDATE_PLAN_APPROVED"
	AuditUpdatePlanCancelled = "UPDATE_PLAN_CANCELLED"

	AuditUpdateExecutionRequested   = "UPDATE_EXECUTION_REQUESTED"
	AuditUpdatePrecheckStarted      = "UPDATE_PRECHECK_STARTED"
	AuditUpdatePrecheckFailed       = "UPDATE_PRECHECK_FAILED"
	AuditUpdateExecutionStarted     = "UPDATE_EXECUTION_STARTED"
	AuditUpdateExecutionCompleted   = "UPDATE_EXECUTION_COMPLETED"
	AuditUpdateExecutionFailed      = "UPDATE_EXECUTION_FAILED"
	AuditUpdateExecutionPartial     = "UPDATE_EXECUTION_PARTIAL"
	AuditUpdateVerificationComplete = "UPDATE_VERIFICATION_COMPLETED"

	AuditRebootRequested           = "REBOOT_REQUESTED"
	AuditRebootPrecheckStarted     = "REBOOT_PRECHECK_STARTED"
	AuditRebootPrecheckFailed      = "REBOOT_PRECHECK_FAILED"
	AuditRebootCommandSent         = "REBOOT_COMMAND_SENT"
	AuditRebootDisconnected        = "REBOOT_DISCONNECTED"
	AuditRebootReconnectStarted    = "REBOOT_RECONNECT_STARTED"
	AuditRebootReconnected         = "REBOOT_RECONNECTED"
	AuditRebootVerificationStarted = "REBOOT_VERIFICATION_STARTED"
	AuditRebootCompleted           = "REBOOT_COMPLETED"
	AuditRebootFailed              = "REBOOT_FAILED"
	AuditRebootTimeout             = "REBOOT_TIMEOUT"
	AuditRebootVerificationRetried = "REBOOT_VERIFICATION_RETRIED"

	AuditDatabaseCreated            = "DATABASE_CREATED"
	AuditDatabaseUpdated            = "DATABASE_UPDATED"
	AuditDatabaseDeleted            = "DATABASE_DELETED"
	AuditDatabaseScanStarted        = "DATABASE_SCAN_STARTED"
	AuditDatabaseScanCompleted      = "DATABASE_SCAN_COMPLETED"
	AuditDatabaseScanFailed         = "DATABASE_SCAN_FAILED"
	AuditDatabaseConnectionTested   = "DATABASE_CONNECTION_TESTED"
	AuditDatabaseMonitoringEnabled  = "DATABASE_MONITORING_ENABLED"
	AuditDatabaseMonitoringDisabled = "DATABASE_MONITORING_DISABLED"
	AuditDatabaseAccessGranted      = "DATABASE_ACCESS_GRANTED"
	AuditDatabaseAccessRevoked      = "DATABASE_ACCESS_REVOKED"

	AuditDatabaseOperationRequested = "DATABASE_OPERATION_REQUESTED"
	AuditDatabaseOperationConfirmed = "DATABASE_OPERATION_CONFIRMED"
	AuditDatabaseOperationStarted   = "DATABASE_OPERATION_STARTED"
	AuditDatabaseOperationCompleted = "DATABASE_OPERATION_COMPLETED"
	AuditDatabaseOperationFailed    = "DATABASE_OPERATION_FAILED"
	AuditDatabaseOperationCancelled = "DATABASE_OPERATION_CANCELLED"
	AuditDatabaseOperationDeleted   = "DATABASE_OPERATION_DELETED"

	AuditObjectStorageCreated            = "OBJECT_STORAGE_CREATED"
	AuditObjectStorageUpdated            = "OBJECT_STORAGE_UPDATED"
	AuditObjectStorageDeleted            = "OBJECT_STORAGE_DELETED"
	AuditObjectStorageConnectionTested   = "OBJECT_STORAGE_CONNECTION_TESTED"
	AuditObjectStorageMonitoringEnabled  = "OBJECT_STORAGE_MONITORING_ENABLED"
	AuditObjectStorageMonitoringDisabled = "OBJECT_STORAGE_MONITORING_DISABLED"
	AuditObjectStorageAccessGranted      = "OBJECT_STORAGE_ACCESS_GRANTED"
	AuditObjectStorageAccessRevoked      = "OBJECT_STORAGE_ACCESS_REVOKED"
	// AuditObjectStorageObjectViewed/Downloaded (Step 17 Phase 4: browser)
	// log only the object's key in Metadata -- never its content, its
	// metadata VALUES, or (for a download) the generated presigned URL
	// itself, which embeds a temporary credential in its query string and
	// is exactly as sensitive as a raw secret for audit-log purposes.
	AuditObjectStorageObjectViewed     = "OBJECT_STORAGE_OBJECT_VIEWED"
	AuditObjectStorageObjectDownloaded = "OBJECT_STORAGE_OBJECT_DOWNLOADED"

	// Step 25: Kubernetes clusters -- mirrors Object Storage's own set
	// exactly (standalone, admin-configured infrastructure resource).
	AuditK8sClusterCreated       = "K8S_CLUSTER_CREATED"
	AuditK8sClusterUpdated       = "K8S_CLUSTER_UPDATED"
	AuditK8sClusterDeleted       = "K8S_CLUSTER_DELETED"
	AuditK8sConnectionTested     = "K8S_CONNECTION_TESTED"
	AuditK8sMonitoringEnabled    = "K8S_MONITORING_ENABLED"
	AuditK8sMonitoringDisabled   = "K8S_MONITORING_DISABLED"
	AuditK8sCredentialConfigured = "K8S_CREDENTIAL_CONFIGURED"
	AuditK8sCredentialReplaced   = "K8S_CREDENTIAL_REPLACED"
	AuditK8sCredentialRemoved    = "K8S_CREDENTIAL_REMOVED"
	AuditK8sDiscoveryStarted     = "K8S_DISCOVERY_STARTED"
	AuditK8sDiscoveryCompleted   = "K8S_DISCOVERY_COMPLETED"
	AuditK8sDiscoveryFailed      = "K8S_DISCOVERY_FAILED"
	// Log streaming: open/close only, exactly like Docker Logs/VM Console
	// -- never a per-line event, and log content is never written to
	// Metadata.
	AuditK8sLogsOpened = "K8S_LOGS_OPENED"
	AuditK8sLogsClosed = "K8S_LOGS_CLOSED"

	// Docker Hosts: a standalone Docker agent target, mirroring the K8s
	// cluster set exactly (same connect-via-bearer-token model).
	AuditDockerHostCreated            = "DOCKER_HOST_CREATED"
	AuditDockerHostDeleted            = "DOCKER_HOST_DELETED"
	AuditDockerHostMonitoringEnabled  = "DOCKER_HOST_MONITORING_ENABLED"
	AuditDockerHostMonitoringDisabled = "DOCKER_HOST_MONITORING_DISABLED"
	AuditDockerHostCredentialIssued   = "DOCKER_HOST_CREDENTIAL_ISSUED"
	AuditDockerHostCredentialReplaced = "DOCKER_HOST_CREDENTIAL_REPLACED"

	// Custom "App Name" labels -- purely cosmetic renames, but audited like
	// every other admin mutation in this app.
	AuditDockerContainerRenamed = "DOCKER_CONTAINER_RENAMED"
	AuditK8sPodRenamed          = "K8S_POD_RENAMED"

	// Folder > Dashboard -- an org entity under Project > Group binding one
	// VM/K8sCluster to a fixed Monitoring/Logs/Alerts tab set (see
	// services/dashboards.go). Distinct from App Folders above.
	AuditDashboardFolderCreated        = "DASHBOARD_FOLDER_CREATED"
	AuditDashboardFolderRenamed        = "DASHBOARD_FOLDER_RENAMED"
	AuditDashboardFolderDeleted        = "DASHBOARD_FOLDER_DELETED"
	AuditDashboardCreated              = "DASHBOARD_CREATED"
	AuditDashboardRenamed              = "DASHBOARD_RENAMED"
	AuditDashboardMoved                = "DASHBOARD_MOVED"
	AuditDashboardDeleted              = "DASHBOARD_DELETED"
	AuditDashboardMonitoringConfigured = "DASHBOARD_MONITORING_CONFIGURED"
	AuditDashboardLogsConfigured       = "DASHBOARD_LOGS_CONFIGURED"

	AuditAlertCreated       = "ALERT_CREATED"
	AuditAlertAcknowledged  = "ALERT_ACKNOWLEDGED"
	AuditAlertResolved      = "ALERT_RESOLVED"
	AuditAlertSuppressed    = "ALERT_SUPPRESSED"
	AuditAlertRuleCreated   = "ALERT_RULE_CREATED"
	AuditAlertRuleUpdated   = "ALERT_RULE_UPDATED"
	AuditAlertRuleDeleted   = "ALERT_RULE_DELETED"
	AuditNotificationSent   = "NOTIFICATION_SENT"
	AuditNotificationFailed = "NOTIFICATION_FAILED"

	// Step 21: /settings. Personal-preference changes (theme, timezone,
	// date format, muted notification categories, display name) all share
	// one event -- there is no meaningful "which field" split an admin
	// reviewing this log would need that Metadata (the fields that
	// actually changed) doesn't already answer. Platform-level
	// General/Monitoring/Security tabs still have no mutation endpoint
	// (genuinely process-startup-frozen config, not runtime-mutable) --
	// but Sign-in Methods (GitHub/Google/SMTP, migration 047) now is,
	// Owner-only, hence the two constants below.
	AuditUserSettingsUpdated         = "USER_SETTINGS_UPDATED"
	AuditUserPasswordChanged         = "USER_PASSWORD_CHANGED"
	AuditNotificationPolicyChanged   = "NOTIFICATION_POLICY_CHANGED"
	AuditPlatformSigninMethodUpdated = "PLATFORM_SIGNIN_METHOD_UPDATED"
	AuditPlatformSigninMethodTested  = "PLATFORM_SIGNIN_METHOD_TESTED"
	// An admin manually sending a one-off test notification to verify a
	// channel's configuration (see NotificationService.SendTest) -- never
	// touches the notifications table itself, but is still an admin action
	// worth a trail.
	AuditNotificationTestSent = "NOTIFICATION_TEST_SENT"

	// Per-VM Docker agent (Docker+Kubernetes monitoring rework, Phase 1).
	// Mirrors K8sCredentialConfigured/Replaced's role -- only the
	// install/token-lifecycle actions are audited, never a metric sample
	// or log line (see docker_agent_hub.go/docker_agent.go).
	AuditDockerAgentInstalled        = "DOCKER_AGENT_INSTALLED"
	AuditDockerAgentTokenRegenerated = "DOCKER_AGENT_TOKEN_REGENERATED"

	// Monitoring/Logs Folder > Dashboard (the model replacing the retired
	// dashboard_folders/dashboards) -- four independent trees
	// (Monitoring>Docker, Monitoring>Kubernetes, Logs>Docker,
	// Logs>Kubernetes), see services/monitoring_dashboards.go.
	AuditMonitoringFolderCreated                     = "MONITORING_FOLDER_CREATED"
	AuditMonitoringFolderRenamed                     = "MONITORING_FOLDER_RENAMED"
	AuditMonitoringFolderDeleted                     = "MONITORING_FOLDER_DELETED"
	AuditMonitoringDashboardCreated                  = "MONITORING_DASHBOARD_CREATED"
	AuditMonitoringDashboardRenamed                  = "MONITORING_DASHBOARD_RENAMED"
	AuditMonitoringDashboardMoved                    = "MONITORING_DASHBOARD_MOVED"
	AuditMonitoringDashboardDeleted                  = "MONITORING_DASHBOARD_DELETED"
	AuditMonitoringDashboardResourceSelectionUpdated = "MONITORING_DASHBOARD_RESOURCE_SELECTION_UPDATED"
	AuditMonitoringDashboardWidgetsUpdated           = "MONITORING_DASHBOARD_WIDGETS_UPDATED"
)

// AuditEvent is one row to append to audit_logs.
type AuditEvent struct {
	UserID       *uuid.UUID
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	IPAddress    string
	UserAgent    string
	Metadata     map[string]any
}

// AuditService appends to the append-only audit_logs table.
type AuditService struct {
	store *repository.Store
}

// NewAuditService creates an AuditService.
func NewAuditService(store *repository.Store) *AuditService {
	return &AuditService{store: store}
}

// Log appends one audit event. Failures are returned to the caller to log
// (via slog) rather than surfaced to the end user -- an audit write failure
// must never block or fail the underlying user-facing operation.
func (a *AuditService) Log(ctx context.Context, event AuditEvent) error {
	metadata := event.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshal audit metadata: %w", err)
	}

	var ipAddr *netip.Addr
	if event.IPAddress != "" {
		if parsed, err := netip.ParseAddr(event.IPAddress); err == nil {
			ipAddr = &parsed
		}
	}

	_, err = a.store.CreateAuditLog(ctx, generated.CreateAuditLogParams{
		UserID:       pgutil.NullUUID(event.UserID),
		Action:       event.Action,
		ResourceType: pgutil.Text(event.ResourceType),
		ResourceID:   pgutil.NullUUID(event.ResourceID),
		IpAddress:    ipAddr,
		UserAgent:    pgutil.Text(event.UserAgent),
		Metadata:     metadataJSON,
	})
	if err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return nil
}

// LogFrom is Log with IPAddress/UserAgent filled in from r, for the common
// case of logging an event triggered directly by an HTTP request.
func (a *AuditService) LogFrom(r *http.Request, event AuditEvent) error {
	event.IPAddress = clientIPFromRequest(r)
	event.UserAgent = r.UserAgent()
	return a.Log(r.Context(), event)
}

func clientIPFromRequest(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
