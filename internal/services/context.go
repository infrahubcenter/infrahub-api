package services

import "context"

type contextKey string

const userContextKey contextKey = "vmcc_authenticated_user"

// WithUser returns a context carrying the authenticated user. Set by
// middleware.RequireAuthentication; read by handlers via UserFromContext.
func WithUser(ctx context.Context, user AuthenticatedUser) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

// UserFromContext retrieves the authenticated user set by
// middleware.RequireAuthentication, if any.
func UserFromContext(ctx context.Context) (AuthenticatedUser, bool) {
	user, ok := ctx.Value(userContextKey).(AuthenticatedUser)
	return user, ok
}
