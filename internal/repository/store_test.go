package repository_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database"
	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/repository"
)

// requires a running PostgreSQL reachable via DATABASE_URL (see
// backend/.env.example); skipped automatically otherwise so `go test ./...`
// still passes in environments without a database.
func newTestStore(t *testing.T) *repository.Store {
	t.Helper()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL not set; skipping repository integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := database.NewPool(ctx, databaseURL, database.PoolConfig{
		MaxConns:       5,
		MinConns:       1,
		ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("connect to database: %v", err)
	}
	t.Cleanup(pool.Close)

	return repository.New(pool)
}

func TestStore_WithTx_CommitsOnSuccess(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	name := "test-workspace-commit-" + time.Now().Format("20060102150405.000000")

	err := store.WithTx(ctx, func(q *generated.Queries) error {
		_, err := q.CreateWorkspace(ctx, generated.CreateWorkspaceParams{Name: name})
		return err
	})
	if err != nil {
		t.Fatalf("WithTx returned error: %v", err)
	}

	rows, err := store.ListWorkspaces(ctx)
	if err != nil {
		t.Fatalf("expected committed workspace to be readable: %v", err)
	}
	var workspace generated.Workspace
	for _, w := range rows {
		if w.Name == name {
			workspace = w
			break
		}
	}
	if workspace.ID == uuid.Nil {
		t.Fatalf("expected committed workspace %q to be readable", name)
	}

	// This test creates a real row outside the transaction under test
	// (the transaction committed), so deactivate it to avoid leaving
	// active clutter behind; there is no delete-by-name query for workspaces.
	if _, err := store.UpdateWorkspace(ctx, generated.UpdateWorkspaceParams{
		ID:          workspace.ID,
		Name:        workspace.Name,
		Description: workspace.Description,
		IsActive:    false,
	}); err != nil {
		t.Fatalf("cleanup deactivate failed: %v", err)
	}
}

func TestStore_WithTx_RollsBackOnError(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	name := "test-workspace-rollback-" + time.Now().Format("20060102150405.000000")
	sentinelErr := errors.New("intentional rollback")

	err := store.WithTx(ctx, func(q *generated.Queries) error {
		if _, err := q.CreateWorkspace(ctx, generated.CreateWorkspaceParams{Name: name}); err != nil {
			return err
		}
		return sentinelErr
	})
	if !errors.Is(err, sentinelErr) {
		t.Fatalf("expected sentinel error, got: %v", err)
	}

	rows, err := store.ListWorkspaces(ctx)
	if err != nil {
		t.Fatalf("list workspaces: %v", err)
	}
	for _, w := range rows {
		if w.Name == name {
			t.Fatal("expected rolled-back workspace to not exist")
		}
	}
}

// TestStore_ListLatestMonitoringStatusByResourceIDs_ReturnsLatestPerResource
// exercises Step 19 Phase 1's new batched query (feeding
// services.DeriveDisplayHealth per VM for the monitoring dashboard, in a
// later phase) in isolation, directly against the generated code -- no HTTP
// handler exists yet that calls it. It seeds two snapshots for one resource
// at different times plus one snapshot for a second resource, then asserts
// the query returns exactly one row per requested resource_id, each row
// carrying that resource's most recent captured_at/status -- and that a
// third resource's snapshot, deliberately left out of the resource_ids
// argument, never leaks into the result.
func TestStore_ListLatestMonitoringStatusByResourceIDs_ReturnsLatestPerResource(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	workspaceName := "test-workspace-monitoring-status-" + time.Now().Format("20060102150405.000000")
	workspace, err := store.CreateWorkspace(ctx, generated.CreateWorkspaceParams{Name: workspaceName})
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	createResource := func(name string) uuid.UUID {
		t.Helper()
		r, err := store.CreateResource(ctx, generated.CreateResourceParams{
			WorkspaceID: workspace.ID, Name: name, ResourceType: "VM",
		})
		if err != nil {
			t.Fatalf("create resource %q: %v", name, err)
		}
		return r.ID
	}
	resourceA := createResource("monitoring-status-resource-a")
	resourceB := createResource("monitoring-status-resource-b")
	// Deliberately excluded from the query below, to prove the batched
	// query only ever returns rows for the requested resource_ids.
	resourceC := createResource("monitoring-status-resource-c")

	insertSnapshot := func(resourceID uuid.UUID, status string) {
		t.Helper()
		if _, err := store.InsertMonitoringSnapshot(ctx, generated.InsertMonitoringSnapshotParams{
			ResourceID: resourceID, Status: pgtype.Text{String: status, Valid: true},
		}); err != nil {
			t.Fatalf("insert monitoring snapshot: %v", err)
		}
	}

	// Resource A gets two snapshots -- an older HEALTHY one, then (after a
	// short sleep so captured_at strictly advances) a newer WARNING one --
	// the query must surface only the newer one.
	insertSnapshot(resourceA, "HEALTHY")
	time.Sleep(10 * time.Millisecond)
	insertSnapshot(resourceA, "WARNING")
	insertSnapshot(resourceB, "CRITICAL")
	insertSnapshot(resourceC, "HEALTHY")

	rows, err := store.ListLatestMonitoringStatusByResourceIDs(ctx, []uuid.UUID{resourceA, resourceB})
	if err != nil {
		t.Fatalf("ListLatestMonitoringStatusByResourceIDs: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want exactly 2 (one per requested resource_id)", len(rows))
	}

	byResource := make(map[uuid.UUID]generated.ListLatestMonitoringStatusByResourceIDsRow, len(rows))
	for _, row := range rows {
		byResource[row.ResourceID] = row
	}

	aRow, ok := byResource[resourceA]
	if !ok {
		t.Fatal("expected a row for resource A")
	}
	if aRow.Status.String != "WARNING" {
		t.Errorf("resource A status = %q, want WARNING (the most recent of its two snapshots)", aRow.Status.String)
	}

	bRow, ok := byResource[resourceB]
	if !ok {
		t.Fatal("expected a row for resource B")
	}
	if bRow.Status.String != "CRITICAL" {
		t.Errorf("resource B status = %q, want CRITICAL", bRow.Status.String)
	}

	if _, leaked := byResource[resourceC]; leaked {
		t.Error("resource C's row leaked into the response even though it was not in resource_ids")
	}
}
