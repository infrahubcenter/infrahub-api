package services

import (
	"time"

	"github.com/google/uuid"
)

// Role names, matching the rows seeded into the roles table (Step 2).
// OWNER sits above ADMIN -- everywhere IsAdmin() gates a capability, an
// Owner passes too (see IsAdmin below); IsOwner() is for the handful of
// genuinely Owner-exclusive things (editing sign-in-method configuration,
// inviting another Owner) that even an Admin cannot do.
const (
	RoleOwner  = "OWNER"
	RoleAdmin  = "ADMIN"
	RoleMember = "MEMBER"
)

// VM permission names, matching the permissions catalog (Step 2).
// vm.reboot (Step 11) is deliberately never added to grantableVMPermissions
// (access.go) -- like vm.execute/vm.update, it exists in the catalog for
// forward compatibility but is never actually grantable to a Member yet,
// so CanAccessVM(member, ..., PermVMReboot) always resolves false and
// only ADMIN's unconditional bypass ever allows a reboot (spec: "Member
// cannot reboot VMs," a hard rule, not merely the current default grant).
const (
	PermVMView    = "vm.view"
	PermVMConnect = "vm.connect"
	PermVMReboot  = "vm.reboot"
	// PermVMMetrics/PermVMUpdates let a Member be granted just the
	// Metrics-and-Logs tree or just the Updates tree on a VM, without the
	// broader vm.view (which also covers the VM detail/Docker/console
	// sections). Every handler in those two trees accepts vm.view OR its
	// own narrower permission -- see CanAccessVMAny's callers.
	PermVMMetrics = "vm.metrics"
	PermVMUpdates = "vm.updates"
)

// Standalone database permission names (Step 13 spec §53/#97), matching
// the permissions catalog (cmd/seed/main.go). database.view/performance
// are the two granted by default group-membership access (mirroring
// vm.view/vm.connect's group-membership grant); database.browser/logs/
// query_details are never included in that default set and must be
// explicitly, individually granted per spec §54-56's "Members should NOT
// automatically get table/document/key browsing, logs, or raw query
// text."
const (
	PermDatabaseView         = "database.view"
	PermDatabasePerformance  = "database.performance"
	PermDatabaseBrowser      = "database.browser"
	PermDatabaseLogs         = "database.logs"
	PermDatabaseQueryDetails = "database.query_details"
)

// Database operation/remediation permission names (Step 14 spec: "Admin-
// only by default... Members: NO database remediation access by
// default"). Like vm.reboot, these exist in the permissions catalog for
// forward compatibility but are never added to any grantable-permissions
// set (access.go) and never granted by group membership -- authorization
// for every operation endpoint is a plain user.IsAdmin() check, not
// CanAccessDatabase, so there is no grant path that could ever let a
// Member execute a database operation.
const (
	PermDatabaseOperationsView    = "database.operations.view"
	PermDatabaseOperationsExecute = "database.operations.execute"
	PermDatabaseOperationsCancel  = "database.operations.cancel"
	PermDatabaseOperationsRetry   = "database.operations.retry"
)

// Standalone object storage permission names (Step 17), matching the
// permissions catalog (cmd/seed/main.go) -- mirrors the standalone
// database permission tiers exactly (identity.go's database.* comment
// above): object_storage.view/monitor are the two granted by default
// group-membership access; object_storage.browser/download are never
// included in that default set and must be explicitly, individually
// granted, matching database.browser/logs/query_details's "no automatic
// deeper access" rule.
const (
	PermObjectStorageView     = "object_storage.view"
	PermObjectStorageMonitor  = "object_storage.monitor"
	PermObjectStorageBrowser  = "object_storage.browser"
	PermObjectStorageDownload = "object_storage.download"
)

// Docker access-grant permission names (Step 24), matching
// docker_access_grants.permission's CHECK constraint
// (migrations/031_docker_access_grants.sql). Deliberately NOT part of the
// generic permissions catalog / resource_permissions grant model every
// other Perm* constant above uses -- these are Project/Group-scoped only
// (never a single VM), granted via DockerAccessService, and checked via
// AuthorizationService.CanAccessDockerFeature rather than CanAccessVM.
// View-only by construction: there is no "manage" tier, matching the
// spec's "view access only, not full access to edit anything."
const (
	PermDockerMonitor = "docker.monitor"
	PermDockerLogs    = "docker.logs"
)

// Kubernetes access-grant permission names (Step 25), matching
// docker_access_grants.permission's widened CHECK constraint
// (migrations/032_k8s_clusters.sql) -- the K8s section reuses the exact
// same Project/Group-scoped grants table Docker introduced, rather than a
// second grants subsystem. See identity.go's Docker permission comment
// above for the shared rationale (view-only, independent of any other
// permission, checked by AuthorizationService.CanAccessDockerFeature).
const (
	PermK8sMonitor = "k8s.monitor"
	PermK8sLogs    = "k8s.logs"
)

// AuthenticatedUser is the identity attached to a request's context by
// RequireAuthentication. Role is resolved fresh from the database on every
// request (see middleware.RequireAuthentication), not trusted purely from
// the JWT, so a role change or deactivation takes effect immediately.
type AuthenticatedUser struct {
	ID    uuid.UUID
	Email string
	Name  string
	Role  string
}

// IsAdmin reports whether the user holds the ADMIN role OR the OWNER role
// -- Owner is a strict superset of Admin, so every existing "Admin always
// has full access" check already covers Owner for free via this one
// method, with zero changes needed at each of its call sites.
func (u AuthenticatedUser) IsAdmin() bool {
	return u.Role == RoleAdmin || u.Role == RoleOwner
}

// IsOwner reports whether the user holds the OWNER role specifically --
// for the small number of capabilities even an Admin cannot reach
// (editing sign-in-method configuration in Settings, inviting/promoting
// another Owner). Never used as a general access gate; IsAdmin() is that.
func (u AuthenticatedUser) IsOwner() bool {
	return u.Role == RoleOwner
}

// UserStatus is a derived (never stored) presentation of a user's account
// state, computed fresh from is_active and last_login_at on every response
// rather than duplicated as a stored enum -- see Step 18 decision #4.
type UserStatus string

const (
	// UserStatusActive is an active account that has logged in at least once.
	UserStatusActive UserStatus = "ACTIVE"
	// UserStatusInvited is an active account that has never logged in --
	// i.e. the temporary password from creation has not yet been used.
	UserStatusInvited UserStatus = "INVITED"
	// UserStatusDisabled is any disabled account, regardless of login
	// history -- disabled always takes precedence over invited/active.
	UserStatusDisabled UserStatus = "DISABLED"
)

// DeriveUserStatus computes a user's display status from their live
// is_active flag and last_login_at column. This is the single source of
// truth for the derivation -- callers must not duplicate this logic.
func DeriveUserStatus(isActive bool, lastLoginAt *time.Time) UserStatus {
	if !isActive {
		return UserStatusDisabled
	}
	if lastLoginAt == nil {
		return UserStatusInvited
	}
	return UserStatusActive
}
