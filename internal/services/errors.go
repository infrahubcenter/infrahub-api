package services

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// Sentinel errors shared by the management services (Workspace, Resource,
// VM, Access). Handlers translate these to HTTP status codes with
// errors.Is rather than string-matching.
var (
	ErrNotFound      = errors.New("not found")
	ErrDuplicateName = errors.New("name already in use")
	ErrValidation    = errors.New("validation failed")

	// Safe resource deletion. Shared by Workspace/VM/Database/Object
	// Storage delete -- every one of them requires the caller to type the
	// resource's exact current name before the backend will act,
	// independent of (and never trusting) any frontend-side check.
	ErrConfirmationMismatch = errors.New("confirmation name does not match")
	// ErrHasDependencies is returned wrapped with a specific, human-readable
	// count (e.g. "this workspace contains 3 VM(s), 1 database(s)") --
	// callers should render err.Error() directly rather than a generic
	// message.
	ErrHasDependencies = errors.New("resource has dependencies")
)

// isUniqueViolation reports whether err is a Postgres unique_violation
// (SQLSTATE 23505), e.g. a duplicate project/group name racing past the
// application-level check under concurrent requests -- the database
// constraint is the final word; this just lets callers turn it into a
// clean ErrDuplicateName instead of a raw 500.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

