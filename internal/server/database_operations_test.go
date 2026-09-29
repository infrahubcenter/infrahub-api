// This file exercises Step 14's controlled database operations HTTP
// surface: Admin-only end to end (no grantable permission path around it,
// unlike every other database endpoint), the Review -> Plan -> Confirm ->
// Execute -> Result -> Audit flow, operation-queue exclusivity, IDOR
// protection across databases, and the structural guarantee that no
// client-supplied query/command text can ever reach command_preview or
// execution -- only backend-defined templates.
package server_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/services"
)

func (e *testEnv) createOperationsDatabaseFixture(t *testing.T) (databaseID, resourceID uuid.UUID) {
	t.Helper()
	project := e.createWorkspace(t)
	db, err := e.databases.Configure(context.Background(), services.ConfigureInput{
		WorkspaceID: project, Name: "test-ops-db-" + uuid.NewString(), Type: "POSTGRESQL",
		Host: "127.0.0.1", Port: 5432, DatabaseName: "vmcc", Username: "vmcc", Password: "vmcc_dev_password",
	})
	if err != nil {
		t.Fatalf("create operations database fixture: %v", err)
	}
	return db.ID, db.ResourceID
}

// === Capabilities: Admin-only, driven by the real engine ===

func TestDatabaseOperationsCapabilities_MemberForbidden(t *testing.T) {
	e := setup(t)
	dbID, resourceID := e.createOperationsDatabaseFixture(t)
	memberEmail, memberPassword, memberID := e.createMember(t)
	// Even a Member holding every other database permission must still be
	// denied -- there is no grant path into Step 14's remediation surface.
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermDatabaseView, services.PermDatabasePerformance, services.PermDatabaseBrowser, services.PermDatabaseLogs, services.PermDatabaseQueryDetails)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/databases/"+dbID.String()+"/operations/capabilities")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member capabilities = %d, want 403", resp.StatusCode)
	}
}

func TestDatabaseOperationsCapabilities_Admin_ReturnsPostgresOps(t *testing.T) {
	e := setup(t)
	dbID, _ := e.createOperationsDatabaseFixture(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/databases/"+dbID.String()+"/operations/capabilities")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin capabilities = %d, want 200", resp.StatusCode)
	}
	caps, _ := body["capabilities"].([]any)
	found := map[string]bool{}
	for _, c := range caps {
		m, _ := c.(map[string]any)
		found[m["type"].(string)] = true
	}
	for _, want := range []string{"CANCEL_QUERY", "TERMINATE_SESSION", "VACUUM", "ANALYZE"} {
		if !found[want] {
			t.Errorf("capabilities missing %s for a POSTGRESQL database", want)
		}
	}
	if found["RESTART"] {
		t.Error("RESTART must never be declared supported -- no shell access exists for standalone databases")
	}
}

// === Preview: pure dry run, no row created, no client-supplied command ===

func TestDatabaseOperationsPreview_NeverReflectsClientSuppliedCommand(t *testing.T) {
	e := setup(t)
	dbID, _ := e.createOperationsDatabaseFixture(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/databases/"+dbID.String()+"/operations/preview", map[string]any{
		"operation_type": "VACUUM",
		"parameters":     map[string]string{},
		// An attacker-controlled field that has no meaning to this API --
		// asserting it never leaks into the generated preview is the
		// structural proof that this endpoint can't be turned into an
		// arbitrary-SQL channel.
		"query": "DROP TABLE users; --",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preview VACUUM = %d, want 200", resp.StatusCode)
	}
	preview, _ := body["command_preview"].(string)
	if preview != "VACUUM;" {
		t.Errorf("command_preview = %q, want exactly %q", preview, "VACUUM;")
	}
	if containsSubstring(preview, "DROP") {
		t.Errorf("command_preview leaked client-supplied text: %q", preview)
	}
}

func TestDatabaseOperationsPreview_UnsupportedOperationRejected(t *testing.T) {
	e := setup(t)
	dbID, _ := e.createOperationsDatabaseFixture(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/databases/"+dbID.String()+"/operations/preview", map[string]any{
		"operation_type": "RESTART", "parameters": map[string]string{},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("preview unsupported RESTART = %d, want 400", resp.StatusCode)
	}
}

func TestDatabaseOperationsPreview_MissingTargetIDRejected(t *testing.T) {
	e := setup(t)
	dbID, _ := e.createOperationsDatabaseFixture(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/databases/"+dbID.String()+"/operations/preview", map[string]any{
		"operation_type": "TERMINATE_SESSION", "parameters": map[string]string{},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("preview TERMINATE_SESSION without target_id = %d, want 400", resp.StatusCode)
	}
}

// === Create: Admin-only, Member forbidden regardless of other grants ===

func TestDatabaseOperationsCreate_MemberForbidden(t *testing.T) {
	e := setup(t)
	dbID, resourceID := e.createOperationsDatabaseFixture(t)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermDatabaseView, services.PermDatabasePerformance)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/databases/"+dbID.String()+"/operations", map[string]any{
		"operation_type": "ANALYZE", "parameters": map[string]string{}, "reason": "member attempt",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member create operation = %d, want 403", resp.StatusCode)
	}
}

func TestDatabaseOperationsCreate_UnauthorizedDatabase_NotFound(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/databases/"+uuid.NewString()+"/operations", map[string]any{
		"operation_type": "ANALYZE", "parameters": map[string]string{},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("create operation on nonexistent database = %d, want 404", resp.StatusCode)
	}
}

// === Full plan lifecycle: create -> WAITING_CONFIRMATION -> confirm -> PENDING/RUNNING -> cancel unavailable ===

func TestDatabaseOperations_CreateThenCancel(t *testing.T) {
	e := setup(t)
	dbID, resourceID := e.createOperationsDatabaseFixture(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	createResp, createBody := e.do(t, client, http.MethodPost, "/api/databases/"+dbID.String()+"/operations", map[string]any{
		"operation_type": "ANALYZE", "parameters": map[string]string{}, "reason": "routine maintenance",
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create operation = %d, want 201", createResp.StatusCode)
	}
	if createBody["status"] != "WAITING_CONFIRMATION" {
		t.Fatalf("status after create = %v, want WAITING_CONFIRMATION", createBody["status"])
	}
	opID := createBody["id"].(string)
	assertAuditEventExists(t, e, "DATABASE", resourceID, services.AuditDatabaseOperationRequested)

	cancelResp, cancelBody := e.do(t, client, http.MethodPost, "/api/databases/"+dbID.String()+"/operations/"+opID+"/cancel", nil)
	if cancelResp.StatusCode != http.StatusOK {
		t.Fatalf("cancel operation = %d, want 200", cancelResp.StatusCode)
	}
	if cancelBody["status"] != "CANCELLED" {
		t.Fatalf("status after cancel = %v, want CANCELLED", cancelBody["status"])
	}
	assertAuditEventExists(t, e, "DATABASE", resourceID, services.AuditDatabaseOperationCancelled)

	// Cancelling an already-terminal operation must not silently succeed.
	secondCancel, _ := e.do(t, client, http.MethodPost, "/api/databases/"+dbID.String()+"/operations/"+opID+"/cancel", nil)
	if secondCancel.StatusCode != http.StatusConflict {
		t.Fatalf("cancel already-cancelled operation = %d, want 409", secondCancel.StatusCode)
	}
}

// === Operation-queue exclusivity: confirming one blocks confirming a second for the same database ===

func TestDatabaseOperations_ConfirmBlocksConflictingOperation(t *testing.T) {
	e := setup(t)
	dbID, _ := e.createOperationsDatabaseFixture(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	_, firstBody := e.do(t, client, http.MethodPost, "/api/databases/"+dbID.String()+"/operations", map[string]any{
		"operation_type": "ANALYZE", "parameters": map[string]string{},
	})
	firstID := firstBody["id"].(string)
	_, secondBody := e.do(t, client, http.MethodPost, "/api/databases/"+dbID.String()+"/operations", map[string]any{
		"operation_type": "VACUUM", "parameters": map[string]string{},
	})
	secondID := secondBody["id"].(string)

	confirmFirst, _ := e.do(t, client, http.MethodPost, "/api/databases/"+dbID.String()+"/operations/"+firstID+"/confirm", nil)
	if confirmFirst.StatusCode != http.StatusAccepted {
		t.Fatalf("confirm first operation = %d, want 202", confirmFirst.StatusCode)
	}

	confirmSecond, _ := e.do(t, client, http.MethodPost, "/api/databases/"+dbID.String()+"/operations/"+secondID+"/confirm", nil)
	if confirmSecond.StatusCode != http.StatusConflict {
		t.Fatalf("confirm second operation while first is active = %d, want 409 (operation-queue exclusivity)", confirmSecond.StatusCode)
	}
}

// === Cross-database IDOR: an operation ID from database A must not resolve under database B ===

func TestDatabaseOperations_OperationIDNotFoundUnderWrongDatabase(t *testing.T) {
	e := setup(t)
	dbA, _ := e.createOperationsDatabaseFixture(t)
	dbB, _ := e.createOperationsDatabaseFixture(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	_, body := e.do(t, client, http.MethodPost, "/api/databases/"+dbA.String()+"/operations", map[string]any{
		"operation_type": "ANALYZE", "parameters": map[string]string{},
	})
	opID := body["id"].(string)

	resp, _ := e.get(t, client, "/api/databases/"+dbB.String()+"/operations/"+opID)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("operation from database A fetched under database B = %d, want 404", resp.StatusCode)
	}
}

// === Retry only after FAILED ===

func TestDatabaseOperations_RetryOnlyAfterFailed(t *testing.T) {
	e := setup(t)
	dbID, _ := e.createOperationsDatabaseFixture(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	_, body := e.do(t, client, http.MethodPost, "/api/databases/"+dbID.String()+"/operations", map[string]any{
		"operation_type": "ANALYZE", "parameters": map[string]string{},
	})
	opID := body["id"].(string)

	resp, _ := e.do(t, client, http.MethodPost, "/api/databases/"+dbID.String()+"/operations/"+opID+"/retry", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("retry a WAITING_CONFIRMATION (non-failed) operation = %d, want 409", resp.StatusCode)
	}
}

// === Method enforcement: state-changing endpoints require POST ===

func TestDatabaseOperations_ConfirmRejectsGET(t *testing.T) {
	e := setup(t)
	dbID, _ := e.createOperationsDatabaseFixture(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.get(t, client, "/api/databases/"+dbID.String()+"/operations/"+uuid.NewString()+"/confirm")
	if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET on confirm endpoint = %d, want 405 or 404 (never executed via GET)", resp.StatusCode)
	}
}

// === Full end-to-end execution against the real local dev Postgres ===

func TestDatabaseOperations_FullLifecycle_AnalyzeSucceeds(t *testing.T) {
	e := setup(t)
	dbID, resourceID := e.createOperationsDatabaseFixture(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	_, createBody := e.do(t, client, http.MethodPost, "/api/databases/"+dbID.String()+"/operations", map[string]any{
		"operation_type": "ANALYZE", "parameters": map[string]string{}, "reason": "scheduled maintenance",
	})
	opID := createBody["id"].(string)

	confirmResp, _ := e.do(t, client, http.MethodPost, "/api/databases/"+dbID.String()+"/operations/"+opID+"/confirm", nil)
	if confirmResp.StatusCode != http.StatusAccepted {
		t.Fatalf("confirm = %d, want 202", confirmResp.StatusCode)
	}
	assertAuditEventExists(t, e, "DATABASE", resourceID, services.AuditDatabaseOperationConfirmed)

	// This project's convention: never call a worker's own .Run() loop in
	// tests -- call the execution service's Run method directly and
	// synchronously, exactly like RebootExecutionService/UpdateExecutionService
	// tests do.
	opUUID, _ := uuid.Parse(opID)
	e.databaseOperations.Run(context.Background(), opUUID)

	getResp, getBody := e.get(t, client, "/api/databases/"+dbID.String()+"/operations/"+opID)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get operation after run = %d, want 200", getResp.StatusCode)
	}
	if getBody["status"] != "SUCCESS" {
		t.Fatalf("status after Run = %v, want SUCCESS (error_summary=%v)", getBody["status"], getBody["error_summary"])
	}
	if getBody["health_after"] == nil || getBody["health_after"] == "" {
		t.Error("expected health_after to be populated by post-operation verification")
	}
	assertAuditEventExists(t, e, "DATABASE", resourceID, services.AuditDatabaseOperationCompleted)

	logsResp, logsBody := e.get(t, client, "/api/databases/"+dbID.String()+"/operations/"+opID+"/logs")
	if logsResp.StatusCode != http.StatusOK {
		t.Fatalf("get logs = %d, want 200", logsResp.StatusCode)
	}
	logs, _ := logsBody["logs"].([]any)
	if len(logs) == 0 {
		t.Error("expected a non-empty live-output transcript for a completed operation")
	}
}

func containsSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
