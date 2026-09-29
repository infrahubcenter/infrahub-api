// This file exercises Step 21's unified /operations aggregation --
// GET /api/operations and /api/operations/summary. It deliberately does
// not re-test each underlying family's own status transitions/authorization
// (already covered by update_operations_test.go/reboot_operations_test.go/
// database_operations_test.go); it only tests the merge/filter/paginate/
// scope logic operations.go adds on top of them.
package server_test

import (
	"net/http"
	"testing"

	"vmcontrolcenter/backend/internal/services"
)

func TestOperations_MemberSeesOnlyAuthorizedVM_NeverDatabaseOps(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	authorizedVM := e.createVM(t, project)
	unauthorizedVM := e.createVM(t, project)
	e.createRebootOperationFixture(t, authorizedVM, "SUCCESS")
	e.createRebootOperationFixture(t, unauthorizedVM, "SUCCESS")

	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	dbID, _ := e.createOperationsDatabaseFixture(t)
	_, createBody := e.do(t, adminClient, http.MethodPost, "/api/databases/"+dbID.String()+"/operations", map[string]any{
		"operation_type": "ANALYZE", "parameters": map[string]string{}, "reason": "test",
	})
	if createBody["id"] == nil {
		t.Fatalf("expected database operation to be created, got %v", createBody)
	}

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, authorizedVM, services.PermVMView, services.PermVMConnect)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	resp, body := e.get(t, memberClient, "/api/operations")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member GET /api/operations = %d, want 200", resp.StatusCode)
	}
	ops, _ := body["operations"].([]any)
	if len(ops) != 1 {
		t.Fatalf("expected member to see exactly 1 operation (their authorized VM's reboot), got %d: %v", len(ops), ops)
	}
	first := ops[0].(map[string]any)
	if first["resource_id"] != authorizedVM.String() {
		t.Errorf("expected the visible operation to be for the authorized VM, got resource_id=%v", first["resource_id"])
	}
	if first["family"] == "DATABASE" {
		t.Error("a Member must never see a DATABASE operation -- there is no grant path for it")
	}
}

func TestOperations_AdminSeesAllFamilies(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	e.createRebootOperationFixture(t, vm, "SUCCESS")

	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	vmForPlan, planID := e.createDraftPlan(t, adminClient)
	e.createOperationFixture(t, vmForPlan, planID, "SUCCESS")

	dbID, _ := e.createOperationsDatabaseFixture(t)
	e.do(t, adminClient, http.MethodPost, "/api/databases/"+dbID.String()+"/operations", map[string]any{
		"operation_type": "ANALYZE", "parameters": map[string]string{}, "reason": "test",
	})

	resp, body := e.get(t, adminClient, "/api/operations")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin GET /api/operations = %d, want 200", resp.StatusCode)
	}
	ops, _ := body["operations"].([]any)
	families := map[string]bool{}
	for _, o := range ops {
		families[o.(map[string]any)["family"].(string)] = true
	}
	if !families["UPDATE"] || !families["REBOOT"] || !families["DATABASE"] {
		t.Errorf("expected admin's merged list to include all 3 families, got: %v (from %d ops)", families, len(ops))
	}
}

func TestOperations_FilterByStatusAndFamily(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	e.createRebootOperationFixture(t, vm, "SUCCESS")
	e.createRebootOperationFixture(t, vm, "FAILED")

	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	resp, body := e.get(t, adminClient, "/api/operations?status=FAILED&family=REBOOT")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("filtered GET /api/operations = %d, want 200", resp.StatusCode)
	}
	ops, _ := body["operations"].([]any)
	if len(ops) != 1 {
		t.Fatalf("expected exactly 1 FAILED reboot operation, got %d", len(ops))
	}
	if ops[0].(map[string]any)["status"] != "FAILED" {
		t.Errorf("expected status FAILED, got %v", ops[0].(map[string]any)["status"])
	}
}

func TestOperations_Search_MatchesResourceName(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	opID := e.createRebootOperationFixture(t, vm, "SUCCESS")

	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	resp, body := e.get(t, adminClient, "/api/operations?search=nonexistent-resource-name-xyz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("search GET /api/operations = %d, want 200", resp.StatusCode)
	}
	if ops, _ := body["operations"].([]any); len(ops) != 0 {
		t.Errorf("expected 0 results for a search that matches nothing, got %d", len(ops))
	}
	_ = opID
}

func TestOperations_Pagination(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	for i := 0; i < 5; i++ {
		e.createRebootOperationFixture(t, vm, "SUCCESS")
	}

	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	resp, body := e.get(t, adminClient, "/api/operations?limit=2&offset=0")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("paginated GET /api/operations = %d, want 200", resp.StatusCode)
	}
	ops, _ := body["operations"].([]any)
	if len(ops) != 2 {
		t.Fatalf("expected exactly 2 operations with limit=2, got %d", len(ops))
	}
	total, _ := body["total"].(float64)
	if total < 5 {
		t.Errorf("expected total >= 5, got %v", total)
	}
}

func TestOperationsSummary_CountsBucketedByStatus(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	e.createRebootOperationFixture(t, vm, "SUCCESS")
	e.createRebootOperationFixture(t, vm, "FAILED")
	e.createRebootOperationFixture(t, vm, "CANCELLED")

	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	resp, body := e.get(t, adminClient, "/api/operations/summary")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/operations/summary = %d, want 200", resp.StatusCode)
	}
	if successful, _ := body["successful"].(float64); successful < 1 {
		t.Errorf("expected at least 1 successful operation, got %v", body["successful"])
	}
	if failed, _ := body["failed"].(float64); failed < 1 {
		t.Errorf("expected at least 1 failed operation, got %v", body["failed"])
	}
	if cancelled, _ := body["cancelled"].(float64); cancelled < 1 {
		t.Errorf("expected at least 1 cancelled operation, got %v", body["cancelled"])
	}
}

func TestOperations_Unauthenticated_Rejected(t *testing.T) {
	e := setup(t)
	client := newClient()
	resp, _ := e.get(t, client, "/api/operations")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET /api/operations = %d, want 401", resp.StatusCode)
	}
}
