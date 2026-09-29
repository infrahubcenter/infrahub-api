-- +goose Up

-- Ensures the OWNER role row exists even in an environment that hasn't
-- re-run `cmd/seed` yet -- the backfill below depends on it, and this
-- keeps the migration self-contained/idempotent on its own.
INSERT INTO roles (name)
SELECT 'OWNER'
WHERE NOT EXISTS (SELECT 1 FROM roles WHERE name = 'OWNER');

-- One-time backfill: promote the earliest-created active ADMIN to OWNER,
-- but only if no OWNER exists yet.
--
-- "The first admin becomes Owner" (services.AuthService.BootstrapAdmin)
-- only covers a *fresh* bootstrap going forward. A deployment that
-- already had its ADMIN account created before this migration would
-- otherwise be left with no OWNER at all -- and since only an existing
-- Owner can ever promote another Owner (see the Owner-only
-- role-assignment gate in internal/handlers/users.go), that would
-- permanently lock Owner out of the deployment with no way to recover
-- through the application itself. This backfill closes that gap exactly
-- once; any deployment that already has an OWNER (including one created
-- by BootstrapAdmin after this migration already ran) is left untouched.
-- +goose StatementBegin
DO $$
DECLARE
    owner_role_id uuid;
    admin_role_id uuid;
    first_admin_id uuid;
BEGIN
    SELECT id INTO owner_role_id FROM roles WHERE name = 'OWNER';
    SELECT id INTO admin_role_id FROM roles WHERE name = 'ADMIN';

    IF owner_role_id IS NULL OR admin_role_id IS NULL THEN
        RETURN;
    END IF;

    IF EXISTS (SELECT 1 FROM user_roles WHERE role_id = owner_role_id) THEN
        RETURN;
    END IF;

    SELECT u.id INTO first_admin_id
    FROM users u
    JOIN user_roles ur ON ur.user_id = u.id
    WHERE ur.role_id = admin_role_id AND u.is_active = true
    ORDER BY u.created_at ASC
    LIMIT 1;

    IF first_admin_id IS NULL THEN
        RETURN;
    END IF;

    DELETE FROM user_roles WHERE user_id = first_admin_id AND role_id = admin_role_id;
    INSERT INTO user_roles (user_id, role_id) VALUES (first_admin_id, owner_role_id);
END $$;
-- +goose StatementEnd

-- +goose Down
-- Not reversed: demoting the backfilled Owner back to Admin on a rollback
-- could leave the deployment with zero Owners, which the application
-- itself refuses to allow via the API (last-active-Owner invariant, see
-- AuthService.UpdateUserAccount). If a rollback is genuinely needed,
-- demote manually with full awareness of that invariant.
