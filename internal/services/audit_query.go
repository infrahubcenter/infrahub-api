// Package services: audit_query.go adds the read side Step 21's /audit-logs
// page needs (list/filter/search/paginate/overview) on top of the existing
// append-only audit_logs table and AuditService.Log write path (audit.go,
// unchanged) -- there is exactly one audit system in this project, this
// only adds a way to browse it.
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// sensitiveMetadataKeyFragments is checked as a case-insensitive substring
// against every metadata key, so "password", "new_password",
// "s3_secret_key", and "sessionToken" are all caught by one entry each.
// AuditService.Log's own callers are already audited (Step 20) never to
// write a secret here in the first place -- this is the display-layer
// backstop Step 21 spec §15 asks for regardless: "Never display... even if
// accidentally present."
var sensitiveMetadataKeyFragments = []string{
	"password", "private_key", "privatekey", "secret", "token", "credential", "api_key", "apikey",
}

func isSensitiveMetadataKey(key string) bool {
	lower := strings.ToLower(key)
	for _, fragment := range sensitiveMetadataKeyFragments {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	return false
}

// redactAuditMetadata parses raw (a jsonb column's bytes) and blanks any
// key matching isSensitiveMetadataKey at every nesting level, recursing
// into nested objects and arrays. Malformed/empty JSON becomes an empty
// map rather than an error -- a display concern should never turn into a
// 500 on an otherwise-valid audit row.
func redactAuditMetadata(raw []byte) map[string]any {
	var parsed map[string]any
	if len(raw) == 0 {
		return map[string]any{}
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return map[string]any{}
	}
	return redactMetadataValue(parsed).(map[string]any)
}

func redactMetadataValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, inner := range val {
			if isSensitiveMetadataKey(k) {
				out[k] = "[REDACTED]"
				continue
			}
			out[k] = redactMetadataValue(inner)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, inner := range val {
			out[i] = redactMetadataValue(inner)
		}
		return out
	default:
		return val
	}
}

// AuditCategory buckets the audit action catalog (audit.go) into the
// coarse groups the /audit-logs page filters by (Step 21 spec §12).
// Mutually exclusive by construction: auditCategoryFor is a single switch,
// so every action maps to exactly one category, never zero or several.
type AuditCategory string

const (
	AuditCategoryAuthentication AuditCategory = "AUTHENTICATION"
	AuditCategoryUsers          AuditCategory = "USERS"
	AuditCategoryPermissions    AuditCategory = "PERMISSIONS"
	AuditCategoryProjects       AuditCategory = "PROJECTS"
	AuditCategoryGroups         AuditCategory = "GROUPS"
	AuditCategoryWorkspaces     AuditCategory = "WORKSPACES"
	AuditCategoryVMs            AuditCategory = "VMS"
	AuditCategoryDocker         AuditCategory = "DOCKER"
	AuditCategoryKubernetes     AuditCategory = "KUBERNETES"
	AuditCategoryDatabases      AuditCategory = "DATABASES"
	AuditCategoryObjectStorage  AuditCategory = "OBJECT_STORAGE"
	AuditCategoryMonitoring     AuditCategory = "MONITORING"
	AuditCategoryAlerts         AuditCategory = "ALERTS"
	AuditCategoryUpdates        AuditCategory = "UPDATES"
	AuditCategoryOperations     AuditCategory = "OPERATIONS"
	AuditCategorySettings       AuditCategory = "SETTINGS"
	AuditCategoryOther          AuditCategory = "OTHER"
)

// auditCategoryFor maps one audit_logs.action value to its category. New
// audit actions must be added here explicitly (falling through to OTHER is
// intentional, not a bug -- it surfaces the gap instead of silently
// mis-bucketing) -- see audit_query_test.go's coverage check that every
// constant in audit.go has an entry here.
func auditCategoryFor(action string) AuditCategory {
	switch action {
	case AuditUserLoginSuccess, AuditUserLoginFailed, AuditUserLogout, AuditUnauthorizedAttempt:
		return AuditCategoryAuthentication
	case AuditUserCreated, AuditUserDisabled, AuditUserEnabled, AuditUserRoleChanged:
		return AuditCategoryUsers
	case AuditVMAccessGranted, AuditVMAccessRevoked, AuditGroupMemberAdded, AuditGroupMemberRemoved,
		AuditWorkspaceMemberAdded, AuditWorkspaceMemberRemoved,
		AuditDatabaseAccessGranted, AuditDatabaseAccessRevoked, AuditObjectStorageAccessGranted, AuditObjectStorageAccessRevoked:
		return AuditCategoryPermissions
	case AuditProjectCreated, AuditProjectUpdated, AuditProjectDeactivated, AuditProjectDeleted:
		return AuditCategoryProjects
	case AuditGroupCreated, AuditGroupUpdated, AuditGroupDeactivated, AuditGroupDeleted:
		return AuditCategoryGroups
	case AuditWorkspaceCreated, AuditWorkspaceUpdated, AuditWorkspaceDeactivated, AuditWorkspaceDeleted:
		return AuditCategoryWorkspaces
	case AuditVMCreated, AuditVMUpdated, AuditVMDeactivated,
		AuditSSHCredentialConfigured, AuditSSHCredentialReplaced, AuditSSHCredentialRemoved,
		AuditSSHKeyCredentialCreated, AuditSSHKeyCredentialRenamed, AuditSSHKeyCredentialDeleted,
		AuditVMSSHKeyAttached, AuditVMSSHKeyDetached,
		AuditSSHConnectionTest, AuditSSHConnectionFailed, AuditSSHHostKeyTrusted, AuditSSHHostKeyChanged,
		AuditVMDiscoveryStarted, AuditVMDiscoveryCompleted, AuditVMDiscoveryFailed,
		AuditPackageScanStarted, AuditPackageScanCompleted, AuditPackageScanFailed,
		AuditPackageMetadataRefreshed, AuditPackageRecommendationAcknowledged, AuditPackageRecommendationDismissed,
		AuditPackageBaselineReset,
		AuditVMAgentInstalled, AuditVMAgentLogsOpened, AuditVMAgentLogsClosed,
		AuditExternalPackageScanStarted, AuditExternalPackageScanCompleted, AuditExternalPackageScanFailed:
		return AuditCategoryVMs
	case AuditDockerScanStarted, AuditDockerScanCompleted, AuditDockerScanFailed,
		AuditDockerAccessGranted, AuditDockerAccessRevoked, AuditDockerLogsOpened, AuditDockerLogsClosed,
		AuditDockerContainerRenamed, AuditDockerAgentInstalled, AuditDockerAgentTokenRegenerated,
		AuditDockerHostCreated, AuditDockerHostDeleted, AuditDockerHostMonitoringEnabled, AuditDockerHostMonitoringDisabled,
		AuditDockerHostCredentialIssued, AuditDockerHostCredentialReplaced:
		return AuditCategoryDocker
	case AuditK8sClusterCreated, AuditK8sClusterUpdated, AuditK8sClusterDeleted, AuditK8sConnectionTested,
		AuditK8sMonitoringEnabled, AuditK8sMonitoringDisabled,
		AuditK8sCredentialConfigured, AuditK8sCredentialReplaced, AuditK8sCredentialRemoved,
		AuditK8sDiscoveryStarted, AuditK8sDiscoveryCompleted, AuditK8sDiscoveryFailed,
		AuditK8sLogsOpened, AuditK8sLogsClosed, AuditK8sAccessGranted, AuditK8sAccessRevoked,
		AuditK8sPodRenamed:
		return AuditCategoryKubernetes
	case AuditUpdateScanStarted, AuditUpdateScanCompleted, AuditUpdateScanFailed,
		AuditUpdatePlanCreated, AuditUpdatePlanValidated, AuditUpdatePlanApproved, AuditUpdatePlanCancelled:
		return AuditCategoryUpdates
	case AuditUpdateExecutionRequested, AuditUpdatePrecheckStarted, AuditUpdatePrecheckFailed,
		AuditUpdateExecutionStarted, AuditUpdateExecutionCompleted, AuditUpdateExecutionFailed,
		AuditUpdateExecutionPartial, AuditUpdateVerificationComplete,
		AuditRebootRequested, AuditRebootPrecheckStarted, AuditRebootPrecheckFailed, AuditRebootCommandSent,
		AuditRebootDisconnected, AuditRebootReconnectStarted, AuditRebootReconnected, AuditRebootVerificationStarted,
		AuditRebootCompleted, AuditRebootFailed, AuditRebootTimeout, AuditRebootVerificationRetried,
		AuditDatabaseOperationRequested, AuditDatabaseOperationConfirmed, AuditDatabaseOperationStarted,
		AuditDatabaseOperationCompleted, AuditDatabaseOperationFailed, AuditDatabaseOperationCancelled,
		AuditDatabaseOperationDeleted:
		return AuditCategoryOperations
	case AuditDatabaseCreated, AuditDatabaseUpdated, AuditDatabaseDeleted,
		AuditDatabaseScanStarted, AuditDatabaseScanCompleted, AuditDatabaseScanFailed,
		AuditDatabaseConnectionTested, AuditDatabaseMonitoringEnabled, AuditDatabaseMonitoringDisabled:
		return AuditCategoryDatabases
	case AuditObjectStorageCreated, AuditObjectStorageUpdated, AuditObjectStorageDeleted,
		AuditObjectStorageConnectionTested, AuditObjectStorageMonitoringEnabled, AuditObjectStorageMonitoringDisabled,
		AuditObjectStorageObjectViewed, AuditObjectStorageObjectDownloaded:
		return AuditCategoryObjectStorage
	case AuditMonitoringCollectTriggered,
		AuditDashboardFolderCreated, AuditDashboardFolderRenamed, AuditDashboardFolderDeleted,
		AuditDashboardCreated, AuditDashboardRenamed, AuditDashboardMoved, AuditDashboardDeleted,
		AuditDashboardMonitoringConfigured, AuditDashboardLogsConfigured,
		AuditMonitoringFolderCreated, AuditMonitoringFolderRenamed, AuditMonitoringFolderDeleted,
		AuditMonitoringDashboardCreated, AuditMonitoringDashboardRenamed, AuditMonitoringDashboardMoved, AuditMonitoringDashboardDeleted,
		AuditMonitoringDashboardResourceSelectionUpdated, AuditMonitoringDashboardWidgetsUpdated:
		return AuditCategoryMonitoring
	case AuditAlertCreated, AuditAlertAcknowledged, AuditAlertResolved, AuditAlertSuppressed,
		AuditAlertRuleCreated, AuditAlertRuleUpdated, AuditAlertRuleDeleted, AuditNotificationSent, AuditNotificationFailed,
		AuditNotificationTestSent:
		return AuditCategoryAlerts
	case AuditUserSettingsUpdated, AuditPlatformSigninMethodUpdated, AuditPlatformSigninMethodTested:
		return AuditCategorySettings
	default:
		return AuditCategoryOther
	}
}

// AuditLogEntry is one row of the /audit-logs list -- the append-only
// audit_logs row plus the actor's display name/email (never re-derived
// from user_id client-side) and its resolved category, with metadata
// already redacted (see redactAuditMetadata) so no handler forgets to.
type AuditLogEntry struct {
	ID           uuid.UUID
	UserID       *uuid.UUID
	ActorName    string
	ActorEmail   string
	Action       string
	Category     AuditCategory
	ResourceType string
	ResourceID   *uuid.UUID
	IPAddress    string
	UserAgent    string
	Metadata     map[string]any
	CreatedAt    time.Time
}

// AuditLogFilter is every optional filter GET /api/audit-logs accepts. A
// zero value (all fields nil/zero) returns the unfiltered list -- callers
// apply authorization (currently: Admin-only, see AuditLogsHandler) before
// this is ever reached, never as a side effect of a filter value.
type AuditLogFilter struct {
	UserID       *uuid.UUID
	Action       string
	Category     AuditCategory
	ResourceType string
	From         *time.Time
	To           *time.Time
	Search       string
	Limit        int32
	Offset       int32
}

// AuditQueryService is the read side of the audit system -- AuditService
// (audit.go) remains the only writer.
type AuditQueryService struct {
	store *repository.Store
}

func NewAuditQueryService(store *repository.Store) *AuditQueryService {
	return &AuditQueryService{store: store}
}

// List returns one page of audit_logs rows matching filter, newest first,
// and the total count of matching rows (for "Showing X-Y of N"). Category
// (unlike every other filter) isn't a real column -- it's applied as a
// post-filter in Go over auditCategoryFor, since the category catalog
// lives in application code, not the schema (see auditCategoryFor's own
// doc comment on why no category column was added).
func (s *AuditQueryService) List(ctx context.Context, filter AuditLogFilter) ([]AuditLogEntry, int64, error) {
	params := generated.ListAuditLogsFilteredParams{
		Limit: filter.Limit, Offset: filter.Offset,
		UserID: pgutil.NullUUID(filter.UserID), Action: pgutil.Text(filter.Action),
		ResourceType: pgutil.Text(filter.ResourceType), Search: pgutil.Text(strings.TrimSpace(filter.Search)),
	}
	if filter.From != nil {
		params.From = pgutil.Timestamptz(*filter.From)
	}
	if filter.To != nil {
		params.To = pgutil.Timestamptz(*filter.To)
	}

	// Category is a Go-side post-filter (see doc comment above): when set,
	// over-fetch enough rows to still fill one page after filtering rather
	// than filtering an already-paginated slice, which would under-fill or
	// empty a page whenever a category is sparse relative to Limit/Offset.
	fetchLimit := params.Limit
	fetchOffset := params.Offset
	if filter.Category != "" {
		fetchLimit = 0 // fetch everything matching the non-category filters; bounded by maxCategoryScan below
		fetchOffset = 0
	}
	if fetchLimit == 0 {
		fetchLimit = maxCategoryScanRows
	}
	params.Limit = fetchLimit
	params.Offset = fetchOffset

	rows, err := s.store.Queries.ListAuditLogsFiltered(ctx, params)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit logs: %w", err)
	}

	entries := make([]AuditLogEntry, 0, len(rows))
	for _, row := range rows {
		entry := toAuditLogEntry(row)
		if filter.Category != "" && entry.Category != filter.Category {
			continue
		}
		entries = append(entries, entry)
	}

	if filter.Category == "" {
		total, err := s.store.Queries.CountAuditLogsFiltered(ctx, generated.CountAuditLogsFilteredParams{
			UserID: params.UserID, Action: params.Action, ResourceType: params.ResourceType,
			From: params.From, To: params.To, Search: params.Search,
		})
		if err != nil {
			return nil, 0, fmt.Errorf("count audit logs: %w", err)
		}
		return entries, total, nil
	}

	// Category filter already applied above over every matching row (up to
	// maxCategoryScanRows) -- total is simply len(entries), then paginate
	// that already-filtered slice in Go.
	total := int64(len(entries))
	start := int(filter.Offset)
	if start > len(entries) {
		start = len(entries)
	}
	end := start + int(filter.Limit)
	if end > len(entries) {
		end = len(entries)
	}
	return entries[start:end], total, nil
}

// maxCategoryScanRows bounds the Go-side category filter/paginate path --
// generous for any realistic audit volume between deployments of this
// admin-only, low-traffic page, while still guaranteeing GET /api/audit-logs
// never loads the *entire* history into memory regardless of table size.
const maxCategoryScanRows = 5000

func toAuditLogEntry(row generated.ListAuditLogsFilteredRow) AuditLogEntry {
	entry := AuditLogEntry{
		ID: row.ID, Action: row.Action, Category: auditCategoryFor(row.Action),
		ResourceType: pgutil.TextOrEmpty(row.ResourceType),
		ActorName:    pgutil.TextOrEmpty(row.ActorName),
		ActorEmail:   pgutil.TextOrEmpty(row.ActorEmail),
		UserAgent:    pgutil.TextOrEmpty(row.UserAgent),
		Metadata:     redactAuditMetadata(row.Metadata),
		CreatedAt:    row.CreatedAt.Time,
	}
	if row.UserID.Valid {
		id := pgutil.UUID(row.UserID)
		entry.UserID = &id
	}
	if row.ResourceID.Valid {
		id := pgutil.UUID(row.ResourceID)
		entry.ResourceID = &id
	}
	if row.IpAddress != nil {
		entry.IPAddress = row.IpAddress.String()
	}
	return entry
}

// AuditOverview backs the /audit-logs page's summary cards.
type AuditOverview struct {
	Total            int64
	Today            int64
	SecurityEvents   int64
	UserChanges      int64
	ResourceChanges  int64
	OperationsEvents int64
}

// Overview computes the summary cards from GetAuditLogActionCounts's
// per-action tallies (cheap: bounded by the number of distinct actions,
// a few dozen, never by row count) bucketed through the same
// auditCategoryFor every list/filter call uses, so the cards and the
// category filter can never disagree about what counts as what.
func (s *AuditQueryService) Overview(ctx context.Context) (AuditOverview, error) {
	actionCounts, err := s.store.Queries.GetAuditLogActionCounts(ctx)
	if err != nil {
		return AuditOverview{}, fmt.Errorf("get audit log action counts: %w", err)
	}
	today, err := s.store.Queries.CountAuditLogsToday(ctx)
	if err != nil {
		return AuditOverview{}, fmt.Errorf("count today's audit logs: %w", err)
	}

	overview := AuditOverview{Today: today}
	for _, row := range actionCounts {
		overview.Total += row.Total
		switch auditCategoryFor(row.Action) {
		case AuditCategoryAuthentication:
			overview.SecurityEvents += row.Total
		case AuditCategoryUsers, AuditCategoryPermissions:
			overview.UserChanges += row.Total
		case AuditCategoryProjects, AuditCategoryGroups, AuditCategoryVMs, AuditCategoryDatabases, AuditCategoryObjectStorage:
			overview.ResourceChanges += row.Total
		case AuditCategoryOperations:
			overview.OperationsEvents += row.Total
		}
	}
	return overview, nil
}
