// Package services holds business logic that sits between HTTP handlers
// and the repository layer: password hashing, token issuance, and the
// authentication/authorization flows built on top of them.
package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// ErrInvalidCredentials covers both "no such user" and "wrong password" --
// the caller must show the same generic message for both so login errors
// don't disclose whether an email is registered.
var ErrInvalidCredentials = errors.New("invalid email or password")

// ErrAccountDisabled is returned internally for audit purposes but callers
// must still surface ErrInvalidCredentials' generic message to the client.
var ErrAccountDisabled = errors.New("account is disabled")

// ErrIncorrectCurrentPassword is ChangePassword's own distinct error --
// unlike Login's ErrInvalidCredentials, this caller is already
// authenticated (no email-enumeration concern), so the handler can and
// should surface a specific "current password is incorrect" message.
var ErrIncorrectCurrentPassword = errors.New("current password is incorrect")

// ErrInvalidRefreshToken covers missing, expired, and revoked refresh
// tokens alike, for the same non-disclosure reason.
var ErrInvalidRefreshToken = errors.New("invalid refresh token")

// ErrNoAccountForEmail is LoginWithVerifiedEmail's (OAuth login) exact
// counterpart to ErrInvalidCredentials -- but unlike password login, it
// is safe to surface this specifically to the caller: an OAuth caller
// can only ever present an email they just proved control of via a real
// provider consent screen, never an arbitrary guess, so there is no
// account-enumeration primitive here to protect against by staying vague.
var ErrNoAccountForEmail = errors.New("no account exists for this email")

// ErrLastActiveAdmin is returned by UpdateUserAccount when a role/status
// change would leave the system with zero active admin-or-owner users --
// the single most safety-critical invariant this service enforces. This
// check always wins even when the caller passed Confirmation: true for a
// self-demotion.
var ErrLastActiveAdmin = errors.New("cannot remove the last active admin")

// ErrLastActiveOwner is returned by UpdateUserAccount when a role/status
// change would leave the system with zero active Owners. Distinct from
// ErrLastActiveAdmin: plenty of Admins might remain, but only an Owner can
// ever create or promote another Owner (handlers/users.go), so losing the
// last one is an unrecoverable lockout, not merely a reduced safety margin.
var ErrLastActiveOwner = errors.New("cannot remove the last active owner")

// ErrSelfDemotionConfirmationRequired is returned by UpdateUserAccount when
// an admin changes their own account out of active-admin status (role away
// from ADMIN, or is_active to false) without setting Confirmation: true.
// Distinct from ErrLastActiveAdmin, which takes precedence over this check.
var ErrSelfDemotionConfirmationRequired = errors.New("confirmation required to change your own admin access")

// ErrCannotDeleteSelf is returned by DeleteUser when actorID == targetID --
// unlike a role/status change (which a self-demotion confirmation can still
// permit), there is no confirmation flag that makes deleting your own
// currently-logged-in account safe: it would either leave you unable to
// undo the action, or (if you're the actor granting yourself an exception)
// defeat the point of the last-active-admin/owner checks below entirely.
var ErrCannotDeleteSelf = errors.New("cannot delete your own account")

// Session is the result of a successful login or refresh: a new access
// token, a new refresh token (plaintext, to be set as an HttpOnly cookie
// and never persisted as-is), and the identity it belongs to.
type Session struct {
	User                  AuthenticatedUser
	AccessToken           string
	AccessTokenExpiresAt  time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
}

// AuthService implements login, refresh, logout, and user bootstrap on top
// of the repository and token services.
type AuthService struct {
	store      *repository.Store
	tokens     *TokenService
	refreshTTL time.Duration
}

// NewAuthService creates an AuthService.
func NewAuthService(store *repository.Store, tokens *TokenService, refreshTTL time.Duration) *AuthService {
	return &AuthService{store: store, tokens: tokens, refreshTTL: refreshTTL}
}

// Login verifies email/password and, on success, issues a new session.
// Every failure path (unknown email, wrong password, disabled account)
// returns ErrInvalidCredentials so the caller can show one generic message;
// the distinct errors are for the caller's own audit logging only.
func (s *AuthService) Login(ctx context.Context, email, password string) (Session, error) {
	row, err := s.store.GetUserWithRoleByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrInvalidCredentials
		}
		return Session{}, fmt.Errorf("load user: %w", err)
	}

	if !row.IsActive {
		return Session{}, ErrAccountDisabled
	}

	ok, err := VerifyPassword(row.PasswordHash, password)
	if err != nil {
		return Session{}, fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		return Session{}, ErrInvalidCredentials
	}

	user := AuthenticatedUser{ID: row.ID, Email: row.Email, Name: row.Name, Role: row.RoleName}
	return s.issueSession(ctx, user)
}

// LoginWithVerifiedEmail is the OAuth-login counterpart to Login: no
// password to verify (the provider already proved the caller controls
// email), invite-only -- looks up an existing, active account by email
// and issues a session, or returns ErrNoAccountForEmail/ErrAccountDisabled
// if none matches. Never creates a new user; OAuth is purely an
// alternate login method for an account an admin already created.
func (s *AuthService) LoginWithVerifiedEmail(ctx context.Context, email string) (Session, error) {
	row, err := s.store.GetUserWithRoleByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrNoAccountForEmail
		}
		return Session{}, fmt.Errorf("load user: %w", err)
	}
	if !row.IsActive {
		return Session{}, ErrAccountDisabled
	}

	user := AuthenticatedUser{ID: row.ID, Email: row.Email, Name: row.Name, Role: row.RoleName}
	return s.issueSession(ctx, user)
}

// Refresh validates a presented refresh token and, if valid, rotates it:
// the old token is revoked and a brand new access/refresh pair is issued.
// Presenting an already-revoked token revokes every refresh token the user
// has, on the assumption that reuse of a revoked token indicates theft.
func (s *AuthService) Refresh(ctx context.Context, refreshTokenPlain string) (Session, error) {
	hash := HashRefreshToken(refreshTokenPlain)

	row, err := s.store.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrInvalidRefreshToken
		}
		return Session{}, fmt.Errorf("load refresh token: %w", err)
	}

	if row.RevokedAt.Valid {
		_ = s.store.RevokeAllRefreshTokensForUser(ctx, row.UserID)
		return Session{}, ErrInvalidRefreshToken
	}
	if row.ExpiresAt.Time.Before(time.Now()) {
		return Session{}, ErrInvalidRefreshToken
	}

	userRow, err := s.store.GetUserWithRoleByID(ctx, row.UserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrInvalidRefreshToken
		}
		return Session{}, fmt.Errorf("load user: %w", err)
	}
	if !userRow.IsActive {
		return Session{}, ErrInvalidRefreshToken
	}

	user := AuthenticatedUser{ID: userRow.ID, Email: userRow.Email, Name: userRow.Name, Role: userRow.RoleName}

	var session Session
	err = s.store.WithTx(ctx, func(q *generated.Queries) error {
		if err := q.TouchRefreshTokenLastUsed(ctx, row.ID); err != nil {
			return fmt.Errorf("touch refresh token: %w", err)
		}
		if err := q.RevokeRefreshToken(ctx, row.ID); err != nil {
			return fmt.Errorf("revoke refresh token: %w", err)
		}

		newSession, err := s.newSessionTx(ctx, q, user)
		if err != nil {
			return err
		}
		session = newSession
		return nil
	})
	if err != nil {
		return Session{}, err
	}

	return session, nil
}

// Logout revokes the refresh token so it can no longer be used to obtain
// new access tokens. It is idempotent: an already-invalid token is not an
// error, since the end state (no valid session) is what logout wants.
func (s *AuthService) Logout(ctx context.Context, refreshTokenPlain string) error {
	if refreshTokenPlain == "" {
		return nil
	}
	hash := HashRefreshToken(refreshTokenPlain)

	row, err := s.store.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("load refresh token: %w", err)
	}

	if err := s.store.RevokeRefreshToken(ctx, row.ID); err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}
	return nil
}

// Me loads the current, live state of userID -- used by GET /api/auth/me
// and by RequireAuthentication so a role change or deactivation is
// reflected immediately rather than trusting stale JWT claims.
func (s *AuthService) Me(ctx context.Context, userID uuid.UUID) (AuthenticatedUser, error) {
	row, err := s.store.GetUserWithRoleByID(ctx, userID)
	if err != nil {
		return AuthenticatedUser{}, err
	}
	if !row.IsActive {
		return AuthenticatedUser{}, ErrAccountDisabled
	}
	return AuthenticatedUser{ID: row.ID, Email: row.Email, Name: row.Name, Role: row.RoleName}, nil
}

// ChangePassword lets any authenticated user (any role) change their own
// password, self-service -- unlike CreateUserWithRole/BootstrapAdmin,
// there's no admin actor and no role to assign, just verify-then-replace.
// Requires the correct current password (ErrIncorrectCurrentPassword if
// not) so a hijacked-but-still-logged-in session can't be used to lock
// the real owner out permanently.
func (s *AuthService) ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	if len(newPassword) < 12 {
		return fmt.Errorf("%w: password must be at least 12 characters", ErrValidation)
	}

	row, err := s.store.GetUserWithRoleByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("load user: %w", err)
	}

	ok, err := VerifyPassword(row.PasswordHash, currentPassword)
	if err != nil {
		return fmt.Errorf("verify current password: %w", err)
	}
	if !ok {
		return ErrIncorrectCurrentPassword
	}

	hash, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if err := s.store.SetUserPasswordHash(ctx, generated.SetUserPasswordHashParams{ID: userID, PasswordHash: hash}); err != nil {
		return fmt.Errorf("set password hash: %w", err)
	}
	return nil
}

// issueSession is Login's exclusive path to session creation (Refresh
// builds its own WithTx around newSessionTx directly -- see Refresh above).
// Because of that, this is exactly the right place to record last_login_at
// atomically with the new session: it only ever fires on a real login,
// never on a token refresh, matching "Last Login" the way a human reads it.
func (s *AuthService) issueSession(ctx context.Context, user AuthenticatedUser) (Session, error) {
	var session Session
	err := s.store.WithTx(ctx, func(q *generated.Queries) error {
		newSession, err := s.newSessionTx(ctx, q, user)
		if err != nil {
			return err
		}
		if err := q.TouchUserLastLogin(ctx, user.ID); err != nil {
			return fmt.Errorf("touch last login: %w", err)
		}
		session = newSession
		return nil
	})
	return session, err
}

func (s *AuthService) newSessionTx(ctx context.Context, q *generated.Queries, user AuthenticatedUser) (Session, error) {
	accessToken, err := s.tokens.IssueAccessToken(user.ID, user.Role)
	if err != nil {
		return Session{}, fmt.Errorf("issue access token: %w", err)
	}

	refreshPlain, refreshHash, err := GenerateRefreshToken()
	if err != nil {
		return Session{}, err
	}
	refreshExpiresAt := time.Now().Add(s.refreshTTL)

	if _, err := q.CreateRefreshToken(ctx, generated.CreateRefreshTokenParams{
		UserID:    user.ID,
		TokenHash: refreshHash,
		ExpiresAt: pgutil.Timestamptz(refreshExpiresAt),
	}); err != nil {
		return Session{}, fmt.Errorf("store refresh token: %w", err)
	}

	return Session{
		User:                  user,
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  time.Now().Add(s.tokens.AccessTTL()),
		RefreshToken:          refreshPlain,
		RefreshTokenExpiresAt: refreshExpiresAt,
	}, nil
}

// CreateUserWithRole creates a new user and assigns them exactly one role,
// atomically. Used by both the admin "create member" API and the admin
// bootstrap command.
//
// If this email belongs to a previously-removed (soft-deleted, see
// migration 056) account, this reactivates that same row instead of
// attempting a fresh INSERT -- users_email_unique has no deleted_at
// exception, so a plain INSERT would always fail with "already exists"
// for an email that was ever used before, permanently blocking re-invites
// of a removed person. Reactivating the same id (rather than deleting the
// old row first and inserting a new one) keeps every historical
// created_by/requested_by/acknowledged_by/audit_logs reference attached to
// one coherent account, matching the reasoning behind soft delete itself.
func (s *AuthService) CreateUserWithRole(ctx context.Context, email, name, password, roleName string) (generated.User, error) {
	hash, err := HashPassword(password)
	if err != nil {
		return generated.User{}, fmt.Errorf("hash password: %w", err)
	}

	var user generated.User
	err = s.store.WithTx(ctx, func(q *generated.Queries) error {
		role, err := q.GetRoleByName(ctx, roleName)
		if err != nil {
			return fmt.Errorf("load role %s: %w", roleName, err)
		}

		existing, err := q.GetUserByEmail(ctx, email)
		if err == nil && existing.DeletedAt.Valid {
			reactivated, err := q.ReactivateUser(ctx, generated.ReactivateUserParams{
				ID: existing.ID, Name: name, PasswordHash: hash,
			})
			if err != nil {
				return fmt.Errorf("reactivate user: %w", err)
			}
			if err := q.RemoveAllUserRoles(ctx, reactivated.ID); err != nil {
				return fmt.Errorf("clear previous roles: %w", err)
			}
			if err := q.AssignUserRole(ctx, generated.AssignUserRoleParams{UserID: reactivated.ID, RoleID: role.ID}); err != nil {
				return fmt.Errorf("assign role: %w", err)
			}
			user = reactivated
			return nil
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("check existing user: %w", err)
		}

		// No existing row (err was ErrNoRows), or one exists but is still
		// active -- the latter falls through to CreateUser exactly as
		// before, which fails on users_email_unique precisely because the
		// email is genuinely still taken.
		created, err := q.CreateUser(ctx, generated.CreateUserParams{
			Email:        email,
			Name:         name,
			PasswordHash: hash,
		})
		if err != nil {
			return fmt.Errorf("create user: %w", err)
		}

		if err := q.AssignUserRole(ctx, generated.AssignUserRoleParams{UserID: created.ID, RoleID: role.ID}); err != nil {
			return fmt.Errorf("assign role: %w", err)
		}

		user = created
		return nil
	})
	return user, err
}

// BootstrapAdmin creates the very first privileged account -- as OWNER,
// not ADMIN, since the account that bootstraps the whole system is exactly
// the one that needs the two Owner-exclusive capabilities (configuring
// sign-in methods, inviting further Owners/Admins/Members) from the start
// -- if (and only if) no admin-or-owner exists yet. Shared by two callers with
// different tolerance for "an admin already exists": the standalone
// cmd/bootstrap-admin CLI (a deliberate one-time action, where that case
// is an error) and cmd/server's own startup, which calls this
// automatically whenever BOOTSTRAP_ADMIN_EMAIL/NAME/PASSWORD are set in
// the environment -- there, "already exists" has to be a quiet no-op
// (created=false, err=nil), since those env vars typically stay set for
// the life of a deployment and every restart after the first successful
// boot must still start cleanly rather than failing on its own prior
// success.
func (s *AuthService) BootstrapAdmin(ctx context.Context, email, name, password string) (created bool, user generated.User, err error) {
	if len(password) < 12 {
		return false, generated.User{}, fmt.Errorf("%w: password must be at least 12 characters", ErrValidation)
	}

	existingAdmins, err := s.store.CountAdminUsers(ctx)
	if err != nil {
		return false, generated.User{}, fmt.Errorf("count existing admins: %w", err)
	}
	if existingAdmins > 0 {
		return false, generated.User{}, nil
	}

	user, err = s.CreateUserWithRole(ctx, email, name, password, RoleOwner)
	if err != nil {
		return false, generated.User{}, fmt.Errorf("create owner: %w", err)
	}
	return true, user, nil
}

// UpdateUserAccountInput is the requested change to a user's account. Every
// field is optional (nil/false means "leave unchanged") so a single request
// can update just the name, just active status, just role, or any
// combination of the three atomically.
type UpdateUserAccountInput struct {
	Name         *string
	IsActive     *bool
	Role         *string // RoleAdmin or RoleMember; nil = unchanged.
	Confirmation bool
}

// UpdateUserAccount applies a name/active-status/role change to targetID on
// behalf of actorID, enforcing this system's two account-safety invariants:
//
//  1. A change can never leave zero active admins (ErrLastActiveAdmin) --
//     this check always wins, even over an explicit Confirmation.
//  2. An admin changing their own account out of active-admin status
//     (demoting their own role, or disabling themselves) must set
//     Confirmation: true (ErrSelfDemotionConfirmationRequired otherwise) --
//     a basic guard against a misclick locking the caller out immediately.
//
// Returns the updated user row and the final role name.
func (s *AuthService) UpdateUserAccount(ctx context.Context, actorID, targetID uuid.UUID, in UpdateUserAccountInput) (generated.User, string, error) {
	var updated generated.User
	var roleFinal string

	err := s.store.WithTx(ctx, func(q *generated.Queries) error {
		// Serializes concurrent role/status-changing requests against each
		// other for the rest of this transaction (released automatically at
		// COMMIT/ROLLBACK). Without it, two concurrent requests targeting
		// two different admins could each read "2 active admins" via
		// CountActiveAdminUsers below, independently conclude their own
		// change is safe, and both commit -- leaving zero. This is a
		// narrow, low-traffic, admin-only code path where that race has a
		// genuinely catastrophic outcome, which is what justifies reaching
		// for an advisory lock here specifically; it is the only one in
		// this codebase and not a pattern to copy elsewhere by default.
		if err := q.LockAdminRoleGuard(ctx); err != nil {
			return fmt.Errorf("acquire admin role guard: %w", err)
		}

		existing, err := q.GetUserWithRoleByID(ctx, targetID)
		if err != nil {
			return fmt.Errorf("load user: %w", err)
		}

		nameFinal := existing.Name
		if in.Name != nil && strings.TrimSpace(*in.Name) != "" {
			nameFinal = strings.TrimSpace(*in.Name)
		}
		isActiveFinal := existing.IsActive
		if in.IsActive != nil {
			isActiveFinal = *in.IsActive
		}
		roleFinal = existing.RoleName
		if in.Role != nil {
			roleFinal = *in.Role
		}

		wasActiveAdmin := existing.IsActive && (existing.RoleName == RoleAdmin || existing.RoleName == RoleOwner)
		willBeActiveAdmin := isActiveFinal && (roleFinal == RoleAdmin || roleFinal == RoleOwner)

		if wasActiveAdmin && !willBeActiveAdmin {
			count, err := q.CountActiveAdminUsers(ctx)
			if err != nil {
				return fmt.Errorf("count active admins: %w", err)
			}
			if count <= 1 {
				return ErrLastActiveAdmin
			}
			if actorID == targetID && !in.Confirmation {
				return ErrSelfDemotionConfirmationRequired
			}
		}

		// Narrower invariant on top of the one above: even with other
		// Admins remaining, never let the last active Owner specifically
		// be demoted/deactivated -- only an Owner can ever create or
		// promote another Owner, so losing the last one is an
		// unrecoverable lockout, not just a reduced safety margin.
		wasActiveOwner := existing.IsActive && existing.RoleName == RoleOwner
		willBeActiveOwner := isActiveFinal && roleFinal == RoleOwner
		if wasActiveOwner && !willBeActiveOwner {
			count, err := q.CountActiveOwnerUsers(ctx)
			if err != nil {
				return fmt.Errorf("count active owners: %w", err)
			}
			if count <= 1 {
				return ErrLastActiveOwner
			}
			if actorID == targetID && !in.Confirmation {
				return ErrSelfDemotionConfirmationRequired
			}
		}

		row, err := q.UpdateUser(ctx, generated.UpdateUserParams{ID: targetID, Name: nameFinal, IsActive: isActiveFinal})
		if err != nil {
			return fmt.Errorf("update user: %w", err)
		}
		updated = row

		if roleFinal != existing.RoleName {
			oldRole, err := q.GetRoleByName(ctx, existing.RoleName)
			if err != nil {
				return fmt.Errorf("load role %s: %w", existing.RoleName, err)
			}
			newRole, err := q.GetRoleByName(ctx, roleFinal)
			if err != nil {
				return fmt.Errorf("load role %s: %w", roleFinal, err)
			}
			if err := q.RemoveUserRole(ctx, generated.RemoveUserRoleParams{UserID: targetID, RoleID: oldRole.ID}); err != nil {
				return fmt.Errorf("remove role: %w", err)
			}
			if err := q.AssignUserRole(ctx, generated.AssignUserRoleParams{UserID: targetID, RoleID: newRole.ID}); err != nil {
				return fmt.Errorf("assign role: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return generated.User{}, "", err
	}

	return updated, roleFinal, nil
}

// DeleteUser removes a user from the active Users list -- a soft delete
// (migration 056), never a real DELETE FROM users; see that migration's
// own doc comment for why. Requires the user's exact current name as
// confirmationName, same convention as every other Delete in this app
// (Workspace/VM/Database/Object Storage). Reuses UpdateUserAccount's
// exact last-active-admin/owner protection (same advisory lock, same
// counts, same errors) since removing a user is just as capable of
// leaving the system with zero active Admins/Owners as demoting/
// deactivating one is -- unlike a demotion, though, there is no
// confirmation flag that makes deleting your own account safe, so that
// case is rejected outright.
func (s *AuthService) DeleteUser(ctx context.Context, actorID, targetID uuid.UUID, confirmationName string) error {
	if actorID == targetID {
		return ErrCannotDeleteSelf
	}
	return s.store.WithTx(ctx, func(q *generated.Queries) error {
		if err := q.LockAdminRoleGuard(ctx); err != nil {
			return fmt.Errorf("acquire admin role guard: %w", err)
		}
		existing, err := q.GetUserWithRoleByID(ctx, targetID)
		if err != nil {
			return fmt.Errorf("load user: %w", err)
		}
		if confirmationName != existing.Name {
			return ErrConfirmationMismatch
		}

		wasActiveAdmin := existing.IsActive && (existing.RoleName == RoleAdmin || existing.RoleName == RoleOwner)
		if wasActiveAdmin {
			count, err := q.CountActiveAdminUsers(ctx)
			if err != nil {
				return fmt.Errorf("count active admins: %w", err)
			}
			if count <= 1 {
				return ErrLastActiveAdmin
			}
		}
		wasActiveOwner := existing.IsActive && existing.RoleName == RoleOwner
		if wasActiveOwner {
			count, err := q.CountActiveOwnerUsers(ctx)
			if err != nil {
				return fmt.Errorf("count active owners: %w", err)
			}
			if count <= 1 {
				return ErrLastActiveOwner
			}
		}

		if _, err := q.SoftDeleteUser(ctx, targetID); err != nil {
			return fmt.Errorf("delete user: %w", err)
		}
		return nil
	})
}
