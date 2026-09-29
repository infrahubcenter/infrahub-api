// Package repository is the data-access layer: it wraps sqlc-generated
// queries with a shared pool and a transaction helper so callers never
// construct pgx transactions directly.
package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"vmcontrolcenter/backend/internal/database/generated"
)

// Store exposes every generated query method directly (via the embedded
// *generated.Queries) plus WithTx for multi-statement transactions.
type Store struct {
	*generated.Queries
	pool *pgxpool.Pool
}

// New creates a Store backed by pool.
func New(pool *pgxpool.Pool) *Store {
	return &Store{
		Queries: generated.New(pool),
		pool:    pool,
	}
}

// WithTx runs fn inside a database transaction. fn receives a *generated.Queries
// bound to the transaction; if fn returns an error the transaction is rolled
// back, otherwise it is committed. Callers never see BEGIN/COMMIT/ROLLBACK.
func (s *Store) WithTx(ctx context.Context, fn func(q *generated.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op; error path is already returned below

	if err := fn(s.Queries.WithTx(tx)); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}
