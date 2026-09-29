// This file exercises the standalone object storage HTTP surface (Step
// 17, Phase 1): IDOR protection (404-not-403) on every object-storage-
// scoped endpoint, Member-vs-Admin permission gating, admin-only CRUD/
// test-connection/access-grant, and that Delete only soft-deletes the
// monitoring registration. Mirrors database_test.go's shape exactly.
package server_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/services"
)

// createObjectStorageFixture configures a standalone object storage
// directly through ObjectStorageService (bypassing HTTP), returning its
// ID and resource ID -- mirrors createDatabaseFixture's "insert the
// fixture directly, test the HTTP surface separately" shape. Provider is
// S3_COMPATIBLE pointed at a fake endpoint since these tests exercise
// authorization, not real S3 connectivity.
func (e *testEnv) createObjectStorageFixture(t *testing.T, workspaceID uuid.UUID) (objectStorageID, resourceID uuid.UUID) {
	t.Helper()
	os, err := e.objectStorages.Configure(context.Background(), services.ConfigureObjectStorageInput{
		WorkspaceID: workspaceID, Name: "test-storage-" + uuid.NewString(), Provider: "S3_COMPATIBLE",
		Endpoint: "http://127.0.0.1:19999", Region: "us-east-1", Bucket: "test-bucket",
		AccessKeyID: "test-access-key", SecretAccessKey: "test-secret-key",
	})
	if err != nil {
		t.Fatalf("create object storage fixture: %v", err)
	}
	return os.ID, os.ResourceID
}

// === GET /api/object-storage/:id (IDOR) ===

func TestObjectStorageGet_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, _ := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String())
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member object storage get = %d, want 404 (existence must not be disclosed)", resp.StatusCode)
	}
}

func TestObjectStorageGet_NonexistentID_NotFound(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+uuid.NewString())
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("nonexistent object storage get = %d, want 404", resp.StatusCode)
	}
}

func TestObjectStorageGet_AuthorizedMember_CanView(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/object-storage/"+osID.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorized member object storage get = %d, want 200", resp.StatusCode)
	}
	if body["provider"] != "S3_COMPATIBLE" {
		t.Errorf("provider = %v, want S3_COMPATIBLE", body["provider"])
	}
	if _, present := body["secret_access_key"]; present {
		t.Errorf("secret_access_key leaked in response: %v", body["secret_access_key"])
	}
	if body["credential_configured"] != true {
		t.Errorf("credential_configured = %v, want true", body["credential_configured"])
	}
}

func TestObjectStorageGet_Admin_NeverNeedsExplicitGrant(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, _ := e.createObjectStorageFixture(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin object storage get = %d, want 200", resp.StatusCode)
	}
}

// === permissions + capabilities fields (frontend tab-hiding contract) ===

func TestObjectStorageGet_ReturnsPermissionsAndCapabilities(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)

	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	adminResp, adminBody := e.get(t, adminClient, "/api/object-storage/"+osID.String())
	if adminResp.StatusCode != http.StatusOK {
		t.Fatalf("admin get = %d, want 200", adminResp.StatusCode)
	}
	adminPerms, _ := adminBody["permissions"].([]any)
	if len(adminPerms) != 4 {
		t.Errorf("admin permissions = %v, want all 4 grantable permissions", adminPerms)
	}
	capabilities, _ := adminBody["capabilities"].(map[string]any)
	if capabilities == nil {
		t.Fatalf("expected a capabilities object in the response, got %v", adminBody["capabilities"])
	}
	if capabilities["logs"] != false {
		t.Errorf("capabilities.logs = %v, want false (no log integration in this step)", capabilities["logs"])
	}
	if capabilities["browser"] != true {
		t.Errorf("capabilities.browser = %v, want true", capabilities["browser"])
	}

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageView)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	memberResp, memberBody := e.get(t, memberClient, "/api/object-storage/"+osID.String())
	if memberResp.StatusCode != http.StatusOK {
		t.Fatalf("member get = %d, want 200", memberResp.StatusCode)
	}
	memberPerms, _ := memberBody["permissions"].([]any)
	if len(memberPerms) != 1 || memberPerms[0] != services.PermObjectStorageView {
		t.Errorf("member permissions = %v, want only object_storage.view", memberPerms)
	}
}

// === POST /api/object-storage (admin-only Configure) ===

func TestObjectStorageConfigure_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/object-storage", map[string]any{
		"workspace_id": project.String(), "provider": "AWS_S3", "bucket": "member-bucket",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member configure object storage = %d, want 403", resp.StatusCode)
	}
}

func TestObjectStorageConfigure_RejectsInvalidProvider(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/object-storage", map[string]any{
		"workspace_id": project.String(), "provider": "AZURE_BLOB", "bucket": "invalid-provider-bucket",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("configure with invalid provider = %d, want 400", resp.StatusCode)
	}
}

func TestObjectStorageConfigure_NeverAcceptsAVMID(t *testing.T) {
	// A object storage is never a VM child -- POST /api/object-storage must
	// succeed with only a project_id -- there is no vm_id field anywhere in
	// the request shape.
	e := setup(t)
	project := e.createWorkspace(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/object-storage", map[string]any{
		"workspace_id": project.String(), "provider": "MINIO", "bucket": "standalone-minio-bucket",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("configure standalone minio object storage = %d, want 201", resp.StatusCode)
	}
	if body["provider"] != "MINIO" {
		t.Errorf("provider = %v, want MINIO", body["provider"])
	}
}

// === PATCH/DELETE /api/object-storage/:id (admin-only) ===

func TestObjectStorageUpdate_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPatch, "/api/object-storage/"+osID.String(), map[string]any{"region": "eu-west-1"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member update object storage = %d, want 403", resp.StatusCode)
	}
}

func TestObjectStorageUpdate_Admin_PartialUpdateOnlyChangesSuppliedFields(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, _ := e.createObjectStorageFixture(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPatch, "/api/object-storage/"+osID.String(), map[string]any{"region": "eu-west-1"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin update object storage = %d, want 200", resp.StatusCode)
	}
	if body["region"] != "eu-west-1" {
		t.Errorf("region = %v, want eu-west-1", body["region"])
	}
	if body["provider"] != "S3_COMPATIBLE" {
		t.Errorf("provider = %v, want unchanged S3_COMPATIBLE", body["provider"])
	}
	if body["bucket"] != "test-bucket" {
		t.Errorf("bucket = %v, want unchanged test-bucket", body["bucket"])
	}
}

func TestObjectStorageDelete_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodDelete, "/api/object-storage/"+osID.String(), nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member delete object storage = %d, want 403", resp.StatusCode)
	}
}

func TestObjectStorageDelete_Admin_SoftDeletesThenNotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	delResp, _ := e.do(t, client, http.MethodDelete, "/api/object-storage/"+osID.String(), map[string]string{"confirmation_name": e.resourceName(t, resourceID)})
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("admin delete object storage = %d, want 200", delResp.StatusCode)
	}

	getResp, _ := e.get(t, client, "/api/object-storage/"+osID.String())
	if getResp.StatusCode != http.StatusNotFound {
		t.Fatalf("get after delete = %d, want 404 (soft-deleted)", getResp.StatusCode)
	}
}

// === POST /api/object-storage/:id/test-connection (admin-only) ===

func TestObjectStorageTestConnection_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/object-storage/"+osID.String()+"/test-connection", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member test-connection = %d, want 403", resp.StatusCode)
	}
}

func TestObjectStorageTestConnection_Admin_ReturnsUnreachableForFakeEndpoint(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, _ := e.createObjectStorageFixture(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/object-storage/"+osID.String()+"/test-connection", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin test-connection = %d, want 200", resp.StatusCode)
	}
	// The fixture points at a closed local port -- never a real bucket, so
	// this must never report CONNECTED, and must never fabricate a status
	// this project's classifier doesn't actually produce.
	if body["connection_status"] == "CONNECTED" {
		t.Errorf("connection_status = %v, want a failure status for an unreachable fake endpoint", body["connection_status"])
	}
}

// === access grant/revoke (Member permissions must be real) ===

func TestObjectStorageAccess_GrantThenRevoke(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	preResp, _ := e.get(t, memberClient, "/api/object-storage/"+osID.String())
	if preResp.StatusCode != http.StatusNotFound {
		t.Fatalf("pre-grant member get = %d, want 404", preResp.StatusCode)
	}

	grantResp, _ := e.do(t, adminClient, http.MethodPost, "/api/object-storage/"+osID.String()+"/access", map[string]any{
		"user_id": memberID.String(), "permissions": []string{services.PermObjectStorageView},
	})
	if grantResp.StatusCode != http.StatusOK {
		t.Fatalf("grant object storage access = %d, want 200", grantResp.StatusCode)
	}
	assertAuditEventExists(t, e, "OBJECT_STORAGE", resourceID, services.AuditObjectStorageAccessGranted)

	postResp, _ := e.get(t, memberClient, "/api/object-storage/"+osID.String())
	if postResp.StatusCode != http.StatusOK {
		t.Fatalf("post-grant member get = %d, want 200", postResp.StatusCode)
	}

	revokeResp, _ := e.do(t, adminClient, http.MethodDelete, "/api/object-storage/"+osID.String()+"/access/"+memberID.String(), nil)
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke object storage access = %d, want 200", revokeResp.StatusCode)
	}
	assertAuditEventExists(t, e, "OBJECT_STORAGE", resourceID, services.AuditObjectStorageAccessRevoked)

	afterRevokeResp, _ := e.get(t, memberClient, "/api/object-storage/"+osID.String())
	if afterRevokeResp.StatusCode != http.StatusNotFound {
		t.Fatalf("post-revoke member get = %d, want 404", afterRevokeResp.StatusCode)
	}
}

func TestObjectStorageAccess_GrantIsAdminOnly(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/object-storage/"+osID.String()+"/access", map[string]any{
		"user_id": memberID.String(), "permissions": []string{services.PermObjectStorageBrowser},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member grant access = %d, want 403", resp.StatusCode)
	}
}

// === group membership grants exactly view+monitor, never browser/download ===

func TestObjectStorageAccess_GroupMembershipGrantsViewAndMonitorOnly(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	osID, _ := e.createObjectStorageFixture(t, workspace)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.addWorkspaceMember(t, workspace, memberID)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	viewResp, body := e.get(t, client, "/api/object-storage/"+osID.String())
	if viewResp.StatusCode != http.StatusOK {
		t.Fatalf("group member object_storage.view (default) = %d, want 200", viewResp.StatusCode)
	}
	perms, _ := body["permissions"].([]any)
	if len(perms) != 2 {
		t.Errorf("group-membership permissions = %v, want exactly [object_storage.monitor, object_storage.view]", perms)
	}
	for _, p := range perms {
		if p == services.PermObjectStorageBrowser || p == services.PermObjectStorageDownload {
			t.Errorf("group membership must never grant %v by default", p)
		}
	}
}

// === GET /api/object-storage/:id/access (Step 18 Phase 2) ===

func TestObjectStorageListAccess_AdminOnly(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String()+"/access")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member list object storage access = %d, want 403", resp.StatusCode)
	}
}

func TestObjectStorageListAccess_MergesDirectAndGroup(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, workspace)

	directEmail, _, directID := e.createMember(t)
	e.grantDirectVMAccess(t, directID, resourceID, services.PermObjectStorageBrowser)

	groupEmail, _, groupMemberID := e.createMember(t)
	e.addWorkspaceMember(t, workspace, groupMemberID)

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/object-storage/"+osID.String()+"/access")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin list object storage access = %d, want 200", resp.StatusCode)
	}
	members, _ := body["members"].([]any)
	if len(members) != 2 {
		t.Fatalf("members = %v, want exactly 2 (direct member + group member)", members)
	}

	var directFound, groupFound bool
	for _, m := range members {
		row := m.(map[string]any)
		switch row["email"] {
		case directEmail:
			directFound = true
			if row["access_source"] != "DIRECT" {
				t.Errorf("direct member access_source = %v, want DIRECT", row["access_source"])
			}
			if row["browser"] != true {
				t.Errorf("direct member browser = %v, want true", row["browser"])
			}
			if row["view"] != false {
				t.Errorf("direct member view = %v, want false (only object_storage.browser was granted)", row["view"])
			}
		case groupEmail:
			groupFound = true
			if row["access_source"] != "WORKSPACE" {
				t.Errorf("workspace member access_source = %v, want WORKSPACE", row["access_source"])
			}
			if row["view"] != true || row["monitor"] != true {
				t.Errorf("group member view/monitor = %v/%v, want true/true", row["view"], row["monitor"])
			}
			if row["browser"] != false || row["download"] != false {
				t.Errorf("group member browser/download = %v/%v, want false/false (never a group default)", row["browser"], row["download"])
			}
		}
	}
	if !directFound || !groupFound {
		t.Fatalf("expected both direct (%s) and group (%s) members in %v", directEmail, groupEmail, members)
	}
}

// === cross-storage IDOR: a permission on storage A must never leak storage B ===

func TestObjectStorageGet_AccessToOneStorageDoesNotLeakAnother(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	storageA, resourceA := e.createObjectStorageFixture(t, project)
	storageB, _ := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceA, services.PermObjectStorageView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	aResp, _ := e.get(t, client, "/api/object-storage/"+storageA.String())
	if aResp.StatusCode != http.StatusOK {
		t.Fatalf("authorized storage A get = %d, want 200", aResp.StatusCode)
	}
	bResp, _ := e.get(t, client, "/api/object-storage/"+storageB.String())
	if bResp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized storage B get = %d, want 404 (access to A must not leak B)", bResp.StatusCode)
	}
}

// === GET /api/object-storage/:id/metrics/current and /metrics/history
// (Step 17 Phase 2) ===

func TestObjectStorageMetricsCurrent_NeverMonitored_ReturnsEmptyBodyNot404(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageMonitor)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/object-storage/"+osID.String()+"/metrics/current")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("never-monitored metrics/current = %d, want 200", resp.StatusCode)
	}
	// Every metric field must be genuinely ABSENT from the JSON, never
	// present as null/0/false -- the frontend's "No metrics collected yet"
	// empty state relies on true field absence.
	for _, field := range []string{"object_count", "total_size_bytes", "requests_per_min", "error_count", "bucket_reachable", "request_latency_ms", "captured_at"} {
		if _, present := body[field]; present {
			t.Errorf("field %q present in never-monitored response: %v", field, body[field])
		}
	}
}

func TestObjectStorageMetricsCurrent_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, _ := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String()+"/metrics/current")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member metrics/current = %d, want 404 (existence must not be disclosed)", resp.StatusCode)
	}
}

// A member holding only object_storage.view (not .monitor) must be
// rejected the same 404-not-403 way as a member with zero permissions --
// this is a permission-tier IDOR check, same shape as the Browser/Download
// permission-tier tests the plan calls for.
func TestObjectStorageMetricsCurrent_ViewOnlyMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String()+"/metrics/current")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("view-only member metrics/current = %d, want 404 (object_storage.monitor required)", resp.StatusCode)
	}
}

func TestObjectStorageMetricsCurrent_CrossStorageIDOR(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	storageA, resourceA := e.createObjectStorageFixture(t, project)
	storageB, _ := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceA, services.PermObjectStorageMonitor)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	aResp, _ := e.get(t, client, "/api/object-storage/"+storageA.String()+"/metrics/current")
	if aResp.StatusCode != http.StatusOK {
		t.Fatalf("authorized storage A metrics/current = %d, want 200", aResp.StatusCode)
	}
	bResp, _ := e.get(t, client, "/api/object-storage/"+storageB.String()+"/metrics/current")
	if bResp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized storage B metrics/current = %d, want 404 (access to A must not leak B)", bResp.StatusCode)
	}
}

func TestObjectStorageMetricsCurrent_Admin_ReturnsCachedSample(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, _ := e.createObjectStorageFixture(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	// A real fast-metrics cycle against the fixture's closed local port:
	// unreachable, so BucketReachable=false/ErrorCount=1 -- collected, not
	// fabricated. This exercises ObjectStorageMetricsService.CollectOne end
	// to end (persist + cache) exactly like the real scheduler would.
	os, err := e.store.GetObjectStorageByID(context.Background(), osID)
	if err != nil {
		t.Fatalf("load object storage fixture: %v", err)
	}
	if err := e.objectStorageMetrics.CollectOne(context.Background(), os); err != nil {
		t.Fatalf("CollectOne: %v", err)
	}

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/object-storage/"+osID.String()+"/metrics/current")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin metrics/current = %d, want 200", resp.StatusCode)
	}
	if body["bucket_reachable"] != false {
		t.Errorf("bucket_reachable = %v, want false for an unreachable fake endpoint", body["bucket_reachable"])
	}
	if _, present := body["captured_at"]; !present {
		t.Errorf("captured_at missing from a response with an actual collected sample")
	}
	// object_count/total_size_bytes/requests_per_min are never collected by
	// the fast (HeadBucket-only) cycle -- must stay absent, not 0.
	for _, field := range []string{"object_count", "total_size_bytes", "requests_per_min"} {
		if _, present := body[field]; present {
			t.Errorf("field %q present after a fast-cycle-only collection: %v", field, body[field])
		}
	}
}

func TestObjectStorageMetricsHistory_EmptyRange_ReturnsEmptyPoints(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageMonitor)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/object-storage/"+osID.String()+"/metrics/history")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("never-monitored metrics/history = %d, want 200", resp.StatusCode)
	}
	points, ok := body["points"].([]any)
	if !ok {
		t.Fatalf("points = %v (%T), want a (possibly empty) array", body["points"], body["points"])
	}
	if len(points) != 0 {
		t.Errorf("points = %v, want empty for a never-monitored storage", points)
	}
}

func TestObjectStorageMetricsHistory_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, _ := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String()+"/metrics/history")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member metrics/history = %d, want 404 (existence must not be disclosed)", resp.StatusCode)
	}
}

// === Step 17 Phase 3: GET .../security, .../growth, .../health, and the
// deep-metrics recommendation sync ===

// createObjectStorageFixtureAtEndpoint mirrors createObjectStorageFixture
// but points at a caller-supplied endpoint (a local httptest fake-S3
// server) instead of a closed port -- needed for tests that actually run
// ObjectStorageDeepMetricsService.CollectDeep end to end, since CollectDeep
// makes real HTTP calls via the AWS SDK against object_storages.endpoint.
func (e *testEnv) createObjectStorageFixtureAtEndpoint(t *testing.T, workspaceID uuid.UUID, endpoint string) (objectStorageID, resourceID uuid.UUID) {
	t.Helper()
	os, err := e.objectStorages.Configure(context.Background(), services.ConfigureObjectStorageInput{
		WorkspaceID: workspaceID, Name: "test-storage-" + uuid.NewString(), Provider: "S3_COMPATIBLE",
		Endpoint: endpoint, Region: "us-east-1", Bucket: "test-bucket",
		AccessKeyID: "test-access-key", SecretAccessKey: "test-secret-key",
	})
	if err != nil {
		t.Fatalf("create object storage fixture at endpoint: %v", err)
	}
	return os.ID, os.ResourceID
}

// xmlOKResponse and xmlErrorResponse write the exact S3 REST XML shapes
// these tests' fake servers need -- routed on the S3 REST sub-resource
// query string (?versioning, ?encryption, ?publicAccessBlock,
// ?policyStatus, ?object-lock, ?list-type=2), confirmed against the AWS
// SDK v2 S3 serializers in object_storage_deep_metrics_collect_test.go.
func xmlOKResponse(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

func xmlErrorResponse(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(fmt.Sprintf(`<Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)))
}

// GET .../security IDOR.

func TestObjectStorageSecurity_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, _ := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String()+"/security")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member security = %d, want 404 (existence must not be disclosed)", resp.StatusCode)
	}
}

func TestObjectStorageSecurity_AuthorizedMember_ReturnsDefaultUnknowns(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/object-storage/"+osID.String()+"/security")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorized member security = %d, want 200", resp.StatusCode)
	}
	// A storage that has never had a deep cycle run must report UNKNOWN for
	// every fact -- never a fabricated ENABLED/DISABLED/PUBLIC/PRIVATE.
	for _, field := range []string{"versioning", "encryption", "object_lock", "public_access"} {
		if body[field] != "UNKNOWN" {
			t.Errorf("security.%s = %v, want UNKNOWN before any deep cycle has run", field, body[field])
		}
	}
}

// GET .../growth IDOR.

func TestObjectStorageGrowth_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, _ := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String()+"/growth")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member growth = %d, want 404 (existence must not be disclosed)", resp.StatusCode)
	}
}

func TestObjectStorageGrowth_NeverCollected_ReturnsEmptyBody(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/object-storage/"+osID.String()+"/growth")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("never-collected growth = %d, want 200", resp.StatusCode)
	}
	for _, field := range []string{"current_bytes", "growth_bytes_per_day", "estimated_30d_growth_bytes"} {
		if _, present := body[field]; present {
			t.Errorf("field %q present before any deep cycle has run: %v", field, body[field])
		}
	}
}

// fakeDeepServerHandler builds a fake-S3 handler for these server-level
// tests: versioning/encryption/object-lock always AccessDenied (kept
// simple -- these tests care about growth/public-access, not every
// security fact), public access controlled by isPublic, and ListObjectsV2
// returns objectCount objects of size 1 byte each (S3_COMPATIBLE has no
// CloudWatch, so this is always the bounded-listing fallback).
func fakeDeepServerHandler(isPublic *atomic.Bool, objectCount int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case q.Has("publicAccessBlock"):
			xmlErrorResponse(w, http.StatusNotFound, "NoSuchPublicAccessBlockConfiguration")
		case q.Has("policyStatus"):
			verdict := "false"
			if isPublic != nil && isPublic.Load() {
				verdict = "true"
			}
			xmlOKResponse(w, `<PolicyStatus><IsPublic>`+verdict+`</IsPublic></PolicyStatus>`)
		case q.Has("versioning"), q.Has("encryption"), q.Has("object-lock"):
			xmlErrorResponse(w, http.StatusForbidden, "AccessDenied")
		case q.Has("list-type"):
			contents := ""
			for i := 0; i < objectCount; i++ {
				contents += fmt.Sprintf(`<Contents><Key>obj-%d.txt</Key><Size>1</Size></Contents>`, i)
			}
			xmlOKResponse(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>test-bucket</Name>`+contents+`<IsTruncated>false</IsTruncated></ListBucketResult>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestObjectStorageGrowth_InsufficientHistory_NoGrowthFigure(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)

	srv := httptest.NewServer(fakeDeepServerHandler(nil, 5))
	defer srv.Close()
	osID, resourceID := e.createObjectStorageFixtureAtEndpoint(t, project, srv.URL)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageView)

	osRow, err := e.store.GetObjectStorageByID(context.Background(), osID)
	if err != nil {
		t.Fatalf("load object storage fixture: %v", err)
	}
	if err := e.objectStorageDeepMetrics.CollectDeep(context.Background(), osRow); err != nil {
		t.Fatalf("CollectDeep: %v", err)
	}

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/object-storage/"+osID.String()+"/growth")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("growth after a single deep cycle = %d, want 200", resp.StatusCode)
	}
	if body["current_bytes"] == nil {
		t.Errorf("current_bytes = %v, want the just-collected size (5 bytes)", body["current_bytes"])
	}
	for _, field := range []string{"growth_bytes_per_day", "estimated_30d_growth_bytes"} {
		if _, present := body[field]; present {
			t.Errorf("field %q present after only ONE deep cycle -- growth must never be reported without >=7 days of real history: %v", field, body[field])
		}
	}
}

func TestObjectStorageGrowth_SufficientHistory_ReturnsGrowthFigure(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)

	srv := httptest.NewServer(fakeDeepServerHandler(nil, 3))
	defer srv.Close()
	osID, resourceID := e.createObjectStorageFixtureAtEndpoint(t, project, srv.URL)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageView)

	// Seed a 6-day-old size sample directly via the store -- this is what
	// GetObjectStorageSizeHistorySince/ComputeGrowthRate need to see
	// real, chronologically-earlier history without waiting real days
	// (plan's own suggested test approach).
	sixDaysAgo := time.Now().Add(-6 * 24 * time.Hour)
	if _, err := e.store.CreateObjectStorageMetric(context.Background(), generated.CreateObjectStorageMetricParams{
		ObjectStorageID: osID, CapturedAt: pgutil.Timestamptz(sixDaysAgo), TotalSizeBytes: pgutil.Int8(1),
		HealthStatus: "UNKNOWN", MetricsStatus: "COMPLETE", MetricDetails: []byte("{}"),
	}); err != nil {
		t.Fatalf("seed historical size sample: %v", err)
	}

	osRow, err := e.store.GetObjectStorageByID(context.Background(), osID)
	if err != nil {
		t.Fatalf("load object storage fixture: %v", err)
	}
	if err := e.objectStorageDeepMetrics.CollectDeep(context.Background(), osRow); err != nil {
		t.Fatalf("CollectDeep: %v", err)
	}

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/object-storage/"+osID.String()+"/growth")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("growth with >=7 days of history = %d, want 200", resp.StatusCode)
	}
	if body["growth_bytes_per_day"] == nil {
		t.Errorf("growth_bytes_per_day = %v, want a real computed rate (6-day-old sample + a fresh one exist)", body["growth_bytes_per_day"])
	}
	if body["estimated_30d_growth_bytes"] == nil {
		t.Errorf("estimated_30d_growth_bytes = %v, want growth_bytes_per_day * 30", body["estimated_30d_growth_bytes"])
	}
}

// GET .../health IDOR.

func TestObjectStorageHealth_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, _ := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String()+"/health")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member health = %d, want 404 (existence must not be disclosed)", resp.StatusCode)
	}
}

func TestObjectStorageHealth_NeverMonitored_ReturnsUnknownWithEmptyReasons(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/object-storage/"+osID.String()+"/health")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("never-monitored health = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "UNKNOWN" {
		t.Errorf("status = %v, want UNKNOWN before any monitoring has run", body["status"])
	}
	reasons, ok := body["reasons"].([]any)
	if !ok {
		t.Fatalf("reasons = %v (%T), want a (possibly empty) array", body["reasons"], body["reasons"])
	}
	if len(reasons) != 0 {
		t.Errorf("reasons = %v, want empty for a never-monitored storage", reasons)
	}
}

// === Deep-metrics recommendation sync: public bucket -> recommendation
// created; bucket becomes private -> recommendation resolved. Also
// verifies GET .../health reflects the same evidence. ===

func TestObjectStorageDeepMetrics_PublicAccessRecommendation_UpsertThenResolve(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)

	var isPublic atomic.Bool
	isPublic.Store(true)
	srv := httptest.NewServer(fakeDeepServerHandler(&isPublic, 0))
	defer srv.Close()

	osID, resourceID := e.createObjectStorageFixtureAtEndpoint(t, project, srv.URL)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageView)

	osRow, err := e.store.GetObjectStorageByID(context.Background(), osID)
	if err != nil {
		t.Fatalf("load object storage fixture: %v", err)
	}
	if err := e.objectStorageDeepMetrics.CollectDeep(context.Background(), osRow); err != nil {
		t.Fatalf("CollectDeep (public): %v", err)
	}

	activeRec := findActiveObjectStorageRecommendation(t, e, resourceID, "OBJECT_STORAGE_PUBLIC_ACCESS")
	if activeRec == nil {
		t.Fatalf("expected an active OBJECT_STORAGE_PUBLIC_ACCESS recommendation after a public-bucket deep cycle")
	}
	if activeRec.Severity != "CRITICAL" {
		t.Errorf("severity = %v, want CRITICAL (OBJECT_STORAGE_PUBLIC_ACCESS_SEVERITY default)", activeRec.Severity)
	}

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	healthResp, healthBody := e.get(t, client, "/api/object-storage/"+osID.String()+"/health")
	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("health after public-bucket deep cycle = %d, want 200", healthResp.StatusCode)
	}
	if healthBody["status"] != "CRITICAL" {
		t.Errorf("health status = %v, want CRITICAL while public access is active", healthBody["status"])
	}
	reasons, _ := healthBody["reasons"].([]any)
	foundReason := false
	for _, r := range reasons {
		if r == "Public access detected" {
			foundReason = true
		}
	}
	if !foundReason {
		t.Errorf("reasons = %v, want it to include %q", reasons, "Public access detected")
	}

	// The bucket becomes private -- the next deep cycle must resolve the
	// recommendation, never leave a stale CRITICAL finding active.
	isPublic.Store(false)
	if err := e.objectStorageDeepMetrics.CollectDeep(context.Background(), osRow); err != nil {
		t.Fatalf("CollectDeep (private): %v", err)
	}
	if rec := findActiveObjectStorageRecommendation(t, e, resourceID, "OBJECT_STORAGE_PUBLIC_ACCESS"); rec != nil {
		t.Errorf("expected OBJECT_STORAGE_PUBLIC_ACCESS to be resolved once the bucket is private, still active: %+v", rec)
	}
}

// findActiveObjectStorageRecommendation returns the resource's active
// (not RESOLVED/DISMISSED) recommendation of the given type, or nil.
func findActiveObjectStorageRecommendation(t *testing.T, e *testEnv, resourceID uuid.UUID, recType string) *generated.Recommendation {
	t.Helper()
	recs, err := e.store.ListRecommendationsByResource(context.Background(), generated.ListRecommendationsByResourceParams{ResourceID: resourceID, Status: ""})
	if err != nil {
		t.Fatalf("list recommendations: %v", err)
	}
	for i := range recs {
		if recs[i].Type == recType && recs[i].Status != "RESOLVED" && recs[i].Status != "DISMISSED" {
			return &recs[i]
		}
	}
	return nil
}

// === Alert engine wiring: alert_rules.sql's new LEFT JOIN object_storages
// + alert_metric_lookup.go's 5 new Resolve() cases, exercised end to end
// through the real AlertEngine (mirrors alerts_test.go's
// TestAlertEngine_ZeroDuration_TriggersImmediately shape). ===

func TestAlertEngine_ObjectStorageUnavailable_TriggersImmediately(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)

	// Simulate a fast-cycle result classifying the bucket as unreachable --
	// alert_metric_lookup.go's MetricObjectStorageUnreachable case reads
	// this directly off object_storages.connection_status.
	if _, err := e.store.UpdateObjectStorageConnectionStatus(context.Background(), generated.UpdateObjectStorageConnectionStatusParams{
		ID: osID, ConnectionStatus: "UNAVAILABLE", HealthStatus: "CRITICAL",
	}); err != nil {
		t.Fatalf("seed connection status: %v", err)
	}

	// threshold=0, duration=0: MetricObjectStorageUnreachable resolves to 1
	// (not CONNECTED), and 1 > 0 breaches on the very first evaluation
	// cycle.
	e.createAlertRuleFixture(t, resourceID, services.AlertTypeObjectStorageUnavailable, 0, 0)
	e.alertEngine.EvaluateOnce(context.Background())

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	resp, body := e.get(t, client, "/api/alerts?resource_id="+resourceID.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list alerts = %d, want 200", resp.StatusCode)
	}
	alerts, _ := body["alerts"].([]any)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want exactly 1 (LEFT JOIN object_storages + MetricObjectStorageUnreachable wiring)", len(alerts))
	}
	first := alerts[0].(map[string]any)
	if first["alert_type"] != "OBJECT_STORAGE_UNAVAILABLE" {
		t.Errorf("alert_type = %v, want OBJECT_STORAGE_UNAVAILABLE", first["alert_type"])
	}
	if first["status"] != "ACTIVE" {
		t.Errorf("status = %v, want ACTIVE", first["status"])
	}
}

func TestAlertEngine_ObjectStorageGrowthPercent_ResolvesFromDeepMetric(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)

	// Seed a deep-metrics row directly -- alert_metric_lookup.go's
	// MetricObjectStorageGrowthPercent case reads the latest
	// object_storage_deep_metrics.growth_percent, exactly what
	// ObjectStorageDeepMetricsService.CollectDeep would have written.
	if _, err := e.store.CreateObjectStorageDeepMetric(context.Background(), generated.CreateObjectStorageDeepMetricParams{
		ObjectStorageID: osID, GrowthPercent: pgtype.Float8{Float64: 42, Valid: true}, MetricsStatus: "COMPLETE", Details: []byte("{}"),
	}); err != nil {
		t.Fatalf("seed deep metric: %v", err)
	}

	e.createAlertRuleFixture(t, resourceID, services.AlertTypeObjectStorageHighGrowth, 20, 0)
	e.alertEngine.EvaluateOnce(context.Background())

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	resp, body := e.get(t, client, "/api/alerts?resource_id="+resourceID.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list alerts = %d, want 200", resp.StatusCode)
	}
	alerts, _ := body["alerts"].([]any)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want exactly 1 (42%% growth_percent > 20%% threshold)", len(alerts))
	}
	if alerts[0].(map[string]any)["alert_type"] != "OBJECT_STORAGE_HIGH_GROWTH" {
		t.Errorf("alert_type = %v, want OBJECT_STORAGE_HIGH_GROWTH", alerts[0].(map[string]any)["alert_type"])
	}
}
