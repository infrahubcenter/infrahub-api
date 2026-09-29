// This file exercises Step 21's /audit-logs read API -- list/filter/
// search/paginate/summary and metadata redaction -- on top of the existing
// append-only audit_logs table (unchanged; internal/services/audit.go
// remains the only writer). Immutability itself (no UPDATE/DELETE through
// normal means) is already enforced at the database level by migration
// 013's triggers, not something an HTTP test can meaningfully re-prove
// beyond "no such route exists," which router.go's route table already
// guarantees by construction (no DELETE/PATCH /api/audit-logs registered).
package server_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"vmcontrolcenter/backend/internal/services"
)

func TestAuditLogs_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/audit-logs")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("member GET /api/audit-logs = %d, want 403", resp.StatusCode)
	}

	resp2, _ := e.get(t, client, "/api/audit-logs/summary")
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("member GET /api/audit-logs/summary = %d, want 403", resp2.StatusCode)
	}
}

func TestAuditLogs_Unauthenticated_Rejected(t *testing.T) {
	e := setup(t)
	client := newClient()
	resp, _ := e.get(t, client, "/api/audit-logs")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET /api/audit-logs = %d, want 401", resp.StatusCode)
	}
}

func TestAuditLogs_AdminSeesOwnLoginEvent(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/audit-logs?action=USER_LOGIN_SUCCESS")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/audit-logs = %d, want 200", resp.StatusCode)
	}
	logs, _ := body["audit_logs"].([]any)
	if len(logs) == 0 {
		t.Fatal("expected at least the admin's own login event")
	}
	entry := logs[0].(map[string]any)
	if entry["action"] != "USER_LOGIN_SUCCESS" {
		t.Errorf("expected action USER_LOGIN_SUCCESS, got %v", entry["action"])
	}
	if entry["category"] != "AUTHENTICATION" {
		t.Errorf("expected category AUTHENTICATION, got %v", entry["category"])
	}
	if entry["actor_email"] != adminEmail {
		t.Errorf("expected actor_email %s, got %v", adminEmail, entry["actor_email"])
	}
}

func TestAuditLogs_FilterByCategory(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	// A second login guarantees at least one more AUTHENTICATION event
	// beyond the one that created the session used to call the API below.
	e.login(t, newClient(), adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/audit-logs?category=AUTHENTICATION")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/audit-logs?category=AUTHENTICATION = %d, want 200", resp.StatusCode)
	}
	logs, _ := body["audit_logs"].([]any)
	if len(logs) == 0 {
		t.Fatal("expected at least one AUTHENTICATION event")
	}
	for _, l := range logs {
		if cat := l.(map[string]any)["category"]; cat != "AUTHENTICATION" {
			t.Errorf("category filter leaked a non-matching row: %v", cat)
		}
	}
}

func TestAuditLogs_Search_MatchesActorEmail(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	// adminEmail contains a "+" (uniqueEmail's disambiguator) -- must be
	// url.QueryEscape'd, not raw-concatenated, or the query string parser
	// decodes it as a literal space and the search silently matches
	// nothing (application/x-www-form-urlencoded's "+"-means-space rule).
	resp, body := e.get(t, client, "/api/audit-logs?search="+url.QueryEscape(adminEmail))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("search GET /api/audit-logs = %d, want 200", resp.StatusCode)
	}
	if logs, _ := body["audit_logs"].([]any); len(logs) == 0 {
		t.Error("expected search by actor email to find the admin's own login event")
	}

	resp2, body2 := e.get(t, client, "/api/audit-logs?search=no-such-actor-xyz-123")
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("search GET /api/audit-logs = %d, want 200", resp2.StatusCode)
	}
	if logs, _ := body2["audit_logs"].([]any); len(logs) != 0 {
		t.Errorf("expected 0 results for a search matching nothing, got %d", len(logs))
	}
}

func TestAuditLogs_Pagination(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	for i := 0; i < 3; i++ {
		e.login(t, newClient(), adminEmail, adminPassword)
	}

	resp, body := e.get(t, client, "/api/audit-logs?limit=1&offset=0")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("paginated GET /api/audit-logs = %d, want 200", resp.StatusCode)
	}
	logs, _ := body["audit_logs"].([]any)
	if len(logs) != 1 {
		t.Fatalf("expected exactly 1 row with limit=1, got %d", len(logs))
	}
	total, _ := body["total"].(float64)
	if total < 4 {
		t.Errorf("expected total >= 4 (4 logins), got %v", total)
	}
}

func TestAuditLogs_Summary_HasNonZeroTotal(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/audit-logs/summary")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/audit-logs/summary = %d, want 200", resp.StatusCode)
	}
	if total, _ := body["total"].(float64); total < 1 {
		t.Errorf("expected total >= 1, got %v", body["total"])
	}
	if security, _ := body["security_events"].(float64); security < 1 {
		t.Errorf("expected security_events >= 1 (the admin's own login), got %v", body["security_events"])
	}
}

// TestAuditLogs_MetadataRedacted writes an audit row whose metadata
// contains a key that should never reach the client (spec §15's explicit
// "never display... even if accidentally present" backstop) directly via
// AuditService, bypassing every existing caller's own discipline about
// what it puts in Metadata, to prove the read path itself redacts
// regardless of what a future/buggy caller might write.
func TestAuditLogs_MetadataRedacted(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	if err := e.audit.Log(context.Background(), services.AuditEvent{
		Action: "TEST_SENSITIVE_METADATA_EVENT",
		Metadata: map[string]any{
			"password":             "hunter2",
			"new_password":         "hunter3",
			"ssh_private_key":      "-----BEGIN OPENSSH PRIVATE KEY-----",
			"database_password":    "s3cr3t",
			"access_token":         "abc.def.ghi",
			"s3_secret_access_key": "AKIA...",
			"safe_field":           "this should survive",
		},
	}); err != nil {
		t.Fatalf("write test audit event: %v", err)
	}

	resp, body := e.get(t, client, "/api/audit-logs?action=TEST_SENSITIVE_METADATA_EVENT")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/audit-logs = %d, want 200", resp.StatusCode)
	}
	logs, _ := body["audit_logs"].([]any)
	if len(logs) != 1 {
		t.Fatalf("expected exactly 1 matching event, got %d", len(logs))
	}
	metadata, _ := logs[0].(map[string]any)["metadata"].(map[string]any)
	for _, key := range []string{"password", "new_password", "ssh_private_key", "database_password", "access_token", "s3_secret_access_key"} {
		if metadata[key] != "[REDACTED]" {
			t.Errorf("expected metadata[%q] to be redacted, got %v", key, metadata[key])
		}
	}
	if metadata["safe_field"] != "this should survive" {
		t.Errorf("expected non-sensitive metadata to survive redaction, got %v", metadata["safe_field"])
	}
}

func TestAuditLogs_NoMutationRoutesExist(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/audit-logs")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/audit-logs = %d, want 200", resp.StatusCode)
	}
	logs, _ := body["audit_logs"].([]any)
	if len(logs) == 0 {
		t.Skip("no audit log rows to attempt to mutate")
	}
	id := logs[0].(map[string]any)["id"].(string)

	for _, method := range []string{http.MethodDelete, http.MethodPatch, http.MethodPut} {
		delResp, _ := e.do(t, client, method, "/api/audit-logs/"+id, nil)
		if delResp.StatusCode != http.StatusNotFound && delResp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/audit-logs/:id = %d, want 404/405 (no such route should exist)", method, delResp.StatusCode)
		}
	}
}
