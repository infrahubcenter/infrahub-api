package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// UserHandler implements admin user management. Every route here is
// mounted behind RequireRole(ADMIN) -- see cmd/server/main.go -- since
// creating, listing, and updating users is an administrative operation,
// not something resolved by per-resource authorization.
//
// Step 18 Phase 3 adds authz/databases/objectStorage: GET /api/users/:id's
// new database_access/object_storage_access fields need the exact same
// "list scoped to this target user's authorized resources" computation
// MyAccessHandler already has for the caller, so UserHandler is
// constructed (see router.go) with the same DatabaseHandler/
// ObjectStorageHandler dependencies and calls the shared
// scopedDatabaseAccess/scopedObjectStorageAccess functions directly,
// targeting an admin-specified user instead of "self".
type UserHandler struct {
	store         *repository.Store
	auth          *services.AuthService
	vms           *services.VMService
	authz         *services.AuthorizationService
	databases     *DatabaseHandler
	objectStorage *ObjectStorageHandler
	audit         *services.AuditService
	// settings/appBaseURL/smtpTimeout build a fresh services.InviteMailer
	// per Create call from whatever SMTP configuration is currently live
	// (DB-backed, Owner-editable, falling back to .env -- see
	// services.PlatformSettingsService's own doc comment) rather than a
	// fixed instance built once at startup, so a credential an Owner just
	// saved through Settings takes effect on the very next invite with no
	// restart.
	settings    *services.PlatformSettingsService
	appBaseURL  string
	smtpTimeout time.Duration
}

// NewUserHandler creates a UserHandler.
func NewUserHandler(
	store *repository.Store, auth *services.AuthService, vms *services.VMService, authz *services.AuthorizationService,
	databases *DatabaseHandler, objectStorage *ObjectStorageHandler, audit *services.AuditService,
	settings *services.PlatformSettingsService, appBaseURL string, smtpTimeout time.Duration,
) *UserHandler {
	return &UserHandler{
		store: store, auth: auth, vms: vms, authz: authz, databases: databases, objectStorage: objectStorage, audit: audit,
		settings: settings, appBaseURL: appBaseURL, smtpTimeout: smtpTimeout,
	}
}

type createUserRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Password string `json:"password,omitempty"`
}

type createUserResponse struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Email             string `json:"email"`
	Role              string `json:"role"`
	IsActive          bool   `json:"is_active"`
	TemporaryPassword string `json:"temporary_password,omitempty"`
}

type userListItem struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Email       string  `json:"email"`
	Role        string  `json:"role"`
	IsActive    bool    `json:"is_active"`
	Status      string  `json:"status"`
	LastLoginAt *string `json:"last_login_at,omitempty"`
	// CreatedAt backs the admin users list's "Created" column (Step 18
	// Phase 4). users.created_at is NOT NULL, but the field stays a
	// pointer/omitempty for consistency with LastLoginAt and every other
	// timestamp field this codebase formats via formatTimestamptz.
	CreatedAt *string `json:"created_at,omitempty"`
}

// toUserListItem builds the list-view shape shared by List/Get, deriving
// Status from the live is_active flag and last_login_at column (see
// services.DeriveUserStatus) rather than trusting a separately-stored value.
// Resource counts are not set here -- callers fill them in from whatever
// source is cheapest for their context (a bulk aggregate map for List, the
// already-fetched access arrays for Get).
func toUserListItem(id uuid.UUID, name, email, role string, isActive bool, lastLoginAt, createdAt pgtype.Timestamptz) userListItem {
	return userListItem{
		ID:          id.String(),
		Name:        name,
		Email:       email,
		Role:        role,
		IsActive:    isActive,
		Status:      string(services.DeriveUserStatus(isActive, pgutil.TimePtr(lastLoginAt))),
		LastLoginAt: formatTimestamptz(lastLoginAt),
		CreatedAt:   formatTimestamptz(createdAt),
	}
}

type workspaceMembership struct {
	WorkspaceID   string `json:"workspace_id"`
	WorkspaceName string `json:"workspace_name"`
}

type userDetailResponse struct {
	userListItem
	Workspaces []workspaceMembership `json:"workspaces"`
	VMs        []vmSummary           `json:"vm_access"`
	// DatabaseAccess/ObjectStorageAccess mirror the exact per-user-scoped
	// shape MyAccessHandler already produces for its own "databases"/
	// "object_storage" sections (via the same scopedDatabaseAccess/
	// scopedObjectStorageAccess functions), just computed for this target
	// user instead of the request's caller.
	DatabaseAccess      []map[string]any `json:"database_access"`
	ObjectStorageAccess []map[string]any `json:"object_storage_access"`
	// ActiveAdminCount lets the frontend pre-emptively disable the role
	// control (an ADMIN target who is currently the sole active admin)
	// without a second fetch -- see AuthService.UpdateUserAccount's own
	// last-active-admin enforcement, which this is purely a UI hint for.
	ActiveAdminCount int64 `json:"active_admin_count"`
}

// Create handles POST /api/users.
func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)
	if req.Role == "" {
		req.Role = services.RoleMember
	}

	if req.Name == "" || req.Email == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name and email are required")
		return
	}
	if req.Role != services.RoleOwner && req.Role != services.RoleAdmin && req.Role != services.RoleMember {
		httpx.WriteError(w, http.StatusBadRequest, "role must be OWNER, ADMIN, or MEMBER")
		return
	}
	// Only an Owner may create another Owner -- an Admin can still freely
	// create Admins/Members exactly as before, this is the one new
	// actor-role-vs-target-role check this app didn't have previously.
	actor, _ := services.UserFromContext(r.Context())
	if req.Role == services.RoleOwner && !actor.IsOwner() {
		httpx.WriteError(w, http.StatusForbidden, "only an Owner can create another Owner")
		return
	}

	temporaryPassword := ""
	password := req.Password
	if password == "" {
		temp, err := services.GenerateTemporaryPassword()
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to generate password")
			return
		}
		password = temp
		temporaryPassword = temp
	} else if len(password) < 8 {
		httpx.WriteError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	created, err := h.auth.CreateUserWithRole(r.Context(), req.Email, req.Name, password, req.Role)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			httpx.WriteError(w, http.StatusConflict, "a user with that email already exists")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID:       &actor.ID,
		Action:       services.AuditUserCreated,
		ResourceType: "USER",
		ResourceID:   &created.ID,
		Metadata:     map[string]any{"email": created.Email, "role": req.Role},
	})

	// Invite email is additive, never a replacement for the temporary
	// password already returned below: if SMTP isn't configured yet, or
	// the send fails, the admin still has the password on-screen to relay
	// manually. Only sent when we generated the password ourselves (an
	// admin-supplied explicit password has nothing new to disclose here).
	// Built fresh from whatever SMTP config is currently live (see this
	// handler's own doc comment) rather than a fixed startup instance.
	if temporaryPassword != "" {
		if live, err := h.settings.Get(r.Context()); err == nil {
			invites := services.NewInviteMailer(live.SMTPHost, live.SMTPPort, live.SMTPUsername, live.SMTPPassword, live.SMTPFromEmail, live.SMTPUseTLS, h.smtpTimeout, h.appBaseURL)
			if invites.Configured() {
				if err := invites.SendInvite(r.Context(), created.Email, created.Name, temporaryPassword); err != nil {
					slog.Warn("invite email failed to send", "user_id", created.ID, "error", err)
				}
			}
		}
	}

	httpx.WriteJSON(w, http.StatusCreated, createUserResponse{
		ID:                created.ID.String(),
		Name:              created.Name,
		Email:             created.Email,
		Role:              req.Role,
		IsActive:          created.IsActive,
		TemporaryPassword: temporaryPassword,
	})
}

// List handles GET /api/users?search=&role=&status=&sort=&order=&limit=&offset=
// (Step 18 Phase 4). Every existing caller -- the VM/Database/ObjectStorage
// AccessSection grant forms and the invite/permissions pages' "pick a
// member" dropdowns -- calls this with zero query params today and expects
// the full, unpaginated {"users": [...]} list back; total/active_admin_count
// are purely additive alongside it, and pagination itself only activates
// once a caller explicitly supplies limit and/or offset, so the zero-params
// contract is preserved exactly rather than silently truncated to a
// default page size.
func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	search := strings.TrimSpace(q.Get("search"))
	role := q.Get("role")
	status := q.Get("status")
	sortBy := q.Get("sort")
	order := q.Get("order")
	_, paginate := q["limit"]
	if _, hasOffset := q["offset"]; hasOffset {
		paginate = true
	}
	limit, offset := parsePagination(r, 25, 100)

	rows, err := h.store.ListUsersFiltered(ctx, generated.ListUsersFilteredParams{
		Search: optionalText(search),
		Role:   optionalText(role),
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load users")
		return
	}

	filtered := make([]userListRow, 0, len(rows))
	for _, row := range rows {
		item := toUserListItem(row.ID, row.Name, row.Email, row.RoleName, row.IsActive, row.LastLoginAt, row.CreatedAt)
		// Status is derived, not a column (services.DeriveUserStatus), so
		// this filter is applied here in Go after the fetch rather than as
		// a SQL predicate -- see ListUsersFiltered's own comment.
		if status != "" && item.Status != status {
			continue
		}
		var lastLogin time.Time
		if row.LastLoginAt.Valid {
			lastLogin = row.LastLoginAt.Time
		}
		filtered = append(filtered, userListRow{item: item, sortLastLogin: lastLogin, sortCreatedAt: row.CreatedAt.Time})
	}

	sortUserListRows(filtered, sortBy, order)

	total := len(filtered)
	if paginate {
		start := int(offset)
		if start > len(filtered) {
			start = len(filtered)
		}
		end := start + int(limit)
		if end > len(filtered) {
			end = len(filtered)
		}
		filtered = filtered[start:end]
	}

	users := make([]userListItem, len(filtered))
	for i, row := range filtered {
		users[i] = row.item
	}

	activeAdminCount, err := h.store.CountActiveAdminUsers(ctx)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load active admin count")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"users": users, "total": total, "active_admin_count": activeAdminCount,
	})
}

// userListRow pairs a userListItem with the raw time.Time sort keys that
// formatTimestamptz already collapsed into an RFC3339 *string on the item
// itself -- kept only for sortUserListRows, never serialized itself.
type userListRow struct {
	item          userListItem
	sortLastLogin time.Time
	sortCreatedAt time.Time
}

// sortUserListRows sorts rows in place by sortBy ("name"|"email"|"role"|
// "status"|"last_login_at"|"created_at", default/unrecognized -> "email")
// and order ("asc"|"desc", default "asc"). Done in Go, not SQL -- no
// dynamic-ORDER BY/query-builder pattern exists anywhere else in this
// codebase, and this is an internal admin list at a scale where an
// in-memory sort after one filtered fetch is simpler and more consistent
// with existing conventions.
func sortUserListRows(rows []userListRow, sortBy, order string) {
	cmp := func(a, b userListRow) int {
		switch sortBy {
		case "name":
			return strings.Compare(strings.ToLower(a.item.Name), strings.ToLower(b.item.Name))
		case "role":
			return strings.Compare(a.item.Role, b.item.Role)
		case "status":
			return strings.Compare(a.item.Status, b.item.Status)
		case "last_login_at":
			return a.sortLastLogin.Compare(b.sortLastLogin)
		case "created_at":
			return a.sortCreatedAt.Compare(b.sortCreatedAt)
		default:
			return strings.Compare(strings.ToLower(a.item.Email), strings.ToLower(b.item.Email))
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		c := cmp(rows[i], rows[j])
		if order == "desc" {
			return c > 0
		}
		return c < 0
	})
}

// loadUserResourceCounts runs the 4 single-pass aggregate queries backing
// List's Workspaces/VMs/Databases/Object Storage columns and indexes each
// into a map[uuid.UUID]int64 -- one query per resource type, not a per-row
// correlated subquery, so this never becomes an N+1 regardless of how many
// users are listed.
// Get handles GET /api/users/:id: profile, workspace access, and
// effective VM/Database/Object Storage access -- the data backing
// /admin/users/:id.
func (h *UserHandler) Get(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "user not found")
		return
	}

	row, err := h.store.GetUserWithRoleByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.WriteError(w, http.StatusNotFound, "user not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load user")
		return
	}

	targetUser := services.AuthenticatedUser{ID: row.ID, Email: row.Email, Name: row.Name, Role: row.RoleName}

	// Derived exactly like My Access's own Workspaces section, just for
	// targetUser instead of the request's caller.
	workspaces, err := workspacesForUser(r.Context(), h.store, targetUser)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load workspace access")
		return
	}

	vmItems, err := h.vms.List(r.Context(), targetUser)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load VM access")
		return
	}
	vms := make([]vmSummary, 0, len(vmItems))
	for _, item := range vmItems {
		vms = append(vms, toVMSummary(item.Detail, item.Permissions, item.Source))
	}

	databaseAccess, err := scopedDatabaseAccess(r, h.store, h.authz, h.databases, targetUser)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load database access")
		return
	}
	objectStorageAccess, err := scopedObjectStorageAccess(r, h.store, h.authz, h.objectStorage, targetUser)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load object storage access")
		return
	}

	activeAdminCount, err := h.store.CountActiveAdminUsers(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load active admin count")
		return
	}

	item := toUserListItem(row.ID, row.Name, row.Email, row.RoleName, row.IsActive, row.LastLoginAt, row.CreatedAt)

	httpx.WriteJSON(w, http.StatusOK, userDetailResponse{
		userListItem:        item,
		Workspaces:          workspaces,
		VMs:                 vms,
		DatabaseAccess:      databaseAccess,
		ObjectStorageAccess: objectStorageAccess,
		ActiveAdminCount:    activeAdminCount,
	})
}

type updateUserRequest struct {
	Name     *string `json:"name,omitempty"`
	IsActive *bool   `json:"is_active,omitempty"`
	// Role, if set, must be ADMIN or MEMBER. Confirmation is required
	// (see AuthService.UpdateUserAccount) only when an admin is changing
	// their own account out of active-admin status.
	Role         *string `json:"role,omitempty"`
	Confirmation bool    `json:"confirmation,omitempty"`
}

// Update handles PATCH /api/users/:id: name, active status, and/or role.
// Role and status changes are delegated to AuthService.UpdateUserAccount,
// which enforces the last-active-admin invariant and the self-demotion
// confirmation gate atomically -- this handler must never fall back to a
// direct store.UpdateUser call for those fields.
func (h *UserHandler) Update(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "user not found")
		return
	}

	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Role != nil && *req.Role != services.RoleOwner && *req.Role != services.RoleAdmin && *req.Role != services.RoleMember {
		httpx.WriteError(w, http.StatusBadRequest, "role must be OWNER, ADMIN, or MEMBER")
		return
	}

	existing, err := h.store.GetUserWithRoleByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.WriteError(w, http.StatusNotFound, "user not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load user")
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	// Only an Owner may promote someone to Owner -- mirrors Create's
	// identical check. Demoting an existing Owner away from OWNER is left
	// to the normal Admin-can-edit-anyone path (still subject to the
	// last-active-owner invariant enforced inside UpdateUserAccount).
	if req.Role != nil && *req.Role == services.RoleOwner && existing.RoleName != services.RoleOwner && !actor.IsOwner() {
		httpx.WriteError(w, http.StatusForbidden, "only an Owner can promote another user to Owner")
		return
	}
	updated, newRole, err := h.auth.UpdateUserAccount(r.Context(), actor.ID, userID, services.UpdateUserAccountInput{
		Name:         req.Name,
		IsActive:     req.IsActive,
		Role:         req.Role,
		Confirmation: req.Confirmation,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.WriteError(w, http.StatusNotFound, "user not found")
			return
		}
		writeServiceError(w, err)
		return
	}

	// One audit event per distinct state transition (mirrors VMHandler.
	// Update's before/after comparison): a single request toggling both
	// active status and role emits both a status event and a role event.
	if existing.IsActive && !updated.IsActive {
		_ = h.audit.LogFrom(r, services.AuditEvent{
			UserID: &actor.ID, Action: services.AuditUserDisabled, ResourceType: "USER", ResourceID: &userID,
		})
	} else if !existing.IsActive && updated.IsActive {
		_ = h.audit.LogFrom(r, services.AuditEvent{
			UserID: &actor.ID, Action: services.AuditUserEnabled, ResourceType: "USER", ResourceID: &userID,
		})
	}
	if newRole != existing.RoleName {
		_ = h.audit.LogFrom(r, services.AuditEvent{
			UserID: &actor.ID, Action: services.AuditUserRoleChanged, ResourceType: "USER", ResourceID: &userID,
			Metadata: map[string]any{"from": existing.RoleName, "to": newRole},
		})
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id":            updated.ID.String(),
		"name":          updated.Name,
		"email":         updated.Email,
		"role":          newRole,
		"is_active":     updated.IsActive,
		"status":        string(services.DeriveUserStatus(updated.IsActive, pgutil.TimePtr(updated.LastLoginAt))),
		"last_login_at": formatTimestamptz(updated.LastLoginAt),
	})
}

// Delete handles DELETE /api/users/:id -- removes the user from the
// active Users list entirely (distinct from Update's is_active
// deactivation, which keeps them listed as Disabled). Permanent and
// irreversible from the UI's own perspective, though it's a soft delete
// underneath (see AuthService.DeleteUser/migration 056): every historical
// record this user is attributed to (audit logs, resources they created,
// operations they requested) keeps resolving to their real name. Requires
// the user's exact current name as confirmation_name, same convention as
// every other Delete in this app.
func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "user not found")
		return
	}
	var req deleteConfirmationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	if err := h.auth.DeleteUser(r.Context(), actor.ID, userID, req.ConfirmationName); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.WriteError(w, http.StatusNotFound, "user not found")
			return
		}
		writeServiceError(w, err)
		return
	}

	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditUserDeleted, ResourceType: "USER", ResourceID: &userID,
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}
