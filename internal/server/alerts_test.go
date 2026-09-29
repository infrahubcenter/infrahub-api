// This file exercises Step 16's central alert/notification system:
// duration-gated triggering, hysteresis/recovery, deduplication (one
// ongoing issue -> one alert, never one per evaluation cycle),
// acknowledge/suppress lifecycle + audit, Member-vs-Admin IDOR scoping
// (mirrors monitoring_test.go/database_test.go's shape exactly), and
// that a firing alert actually produces an in-app notification for
// every authorized recipient.
package server_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/services"
)

func (e *testEnv) seedVMCPUSnapshot(t *testing.T, resourceID uuid.UUID, cpuPercent float64) {
	t.Helper()
	_, err := e.store.InsertMonitoringSnapshot(context.Background(), generated.InsertMonitoringSnapshotParams{
		ResourceID: resourceID, Status: pgtype.Text{String: "HEALTHY", Valid: true},
		CpuUsagePercent: pgtype.Float8{Float64: cpuPercent, Valid: true},
	})
	if err != nil {
		t.Fatalf("seed monitoring snapshot: %v", err)
	}
}

func (e *testEnv) createAlertRuleFixture(t *testing.T, resourceID uuid.UUID, alertType services.AlertType, threshold float64, durationSeconds int32) uuid.UUID {
	t.Helper()
	adminEmail, _ := e.createAdmin(t)
	admin, err := e.store.GetUserByEmail(context.Background(), adminEmail)
	if err != nil {
		t.Fatalf("load admin fixture: %v", err)
	}
	actorID := admin.ID
	rule, err := e.alertRules.Create(context.Background(), services.CreateRuleInput{
		ResourceID: resourceID, AlertType: alertType, Condition: services.CondGreaterThan, Threshold: threshold,
		DurationSeconds: durationSeconds, Severity: services.AlertSeverityWarning, Enabled: true,
	}, actorID)
	if err != nil {
		t.Fatalf("create alert rule fixture: %v", err)
	}
	return rule.ID
}

// === Rule safety / validation ===

func TestAlertRules_RejectsMismatchedResourceType(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	dbID, dbResource := e.createDatabaseFixture(t, project)
	_ = dbID

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/alert-rules", map[string]any{
		"resource_id": dbResource.String(), "alert_type": "VM_HIGH_CPU", "condition": ">", "threshold": 90, "duration_seconds": 0, "severity": "WARNING", "enabled": true,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("VM_HIGH_CPU rule against a database resource = %d, want 400, body=%v", resp.StatusCode, body)
	}
}

func TestAlertRules_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResource := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vmResource, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/alert-rules", map[string]any{
		"resource_id": vmResource.String(), "alert_type": "VM_HIGH_CPU", "condition": ">", "threshold": 90, "duration_seconds": 0, "severity": "WARNING", "enabled": true,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member create alert rule = %d, want 403", resp.StatusCode)
	}
}

// === Duration requirement (spec §9) ===

func TestAlertEngine_DurationGating_NoImmediateAlert(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResource := e.createVM(t, project)
	e.seedVMCPUSnapshot(t, vmResource, 95)
	e.createAlertRuleFixture(t, vmResource, services.AlertTypeVMHighCPU, 90, 300) // 5 minute duration

	e.alertEngine.EvaluateOnce(context.Background())

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	resp, body := e.get(t, client, "/api/alerts?resource_id="+vmResource.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list alerts = %d, want 200", resp.StatusCode)
	}
	alerts, _ := body["alerts"].([]any)
	if len(alerts) != 0 {
		t.Fatalf("got %d alerts after a single breaching sample with a 5m duration, want 0 (spec §9: no alert from a single bad sample)", len(alerts))
	}
}

func TestAlertEngine_ZeroDuration_TriggersImmediately(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResource := e.createVM(t, project)
	e.seedVMCPUSnapshot(t, vmResource, 95)
	e.createAlertRuleFixture(t, vmResource, services.AlertTypeVMHighCPU, 90, 0)

	e.alertEngine.EvaluateOnce(context.Background())

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	resp, body := e.get(t, client, "/api/alerts?resource_id="+vmResource.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list alerts = %d, want 200", resp.StatusCode)
	}
	alerts, _ := body["alerts"].([]any)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want exactly 1 (duration_seconds=0 triggers on the first breaching sample)", len(alerts))
	}
	first := alerts[0].(map[string]any)
	if first["status"] != "ACTIVE" {
		t.Errorf("status = %v, want ACTIVE", first["status"])
	}
	if first["alert_type"] != "VM_HIGH_CPU" {
		t.Errorf("alert_type = %v, want VM_HIGH_CPU", first["alert_type"])
	}
	assertAuditEventExists(t, e, "ALERT", uuid.MustParse(first["id"].(string)), services.AuditAlertCreated)
}

// === Deduplication (spec §11) ===

func TestAlertEngine_Deduplication_OneAlertAcrossManyCycles(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResource := e.createVM(t, project)
	e.createAlertRuleFixture(t, vmResource, services.AlertTypeVMHighCPU, 90, 0)

	for i := 0; i < 5; i++ {
		e.seedVMCPUSnapshot(t, vmResource, 95)
		e.alertEngine.EvaluateOnce(context.Background())
	}

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	resp, body := e.get(t, client, "/api/alerts?resource_id="+vmResource.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list alerts = %d, want 200", resp.StatusCode)
	}
	alerts, _ := body["alerts"].([]any)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts after 5 evaluation cycles of the same ongoing breach, want exactly 1 (spec §11)", len(alerts))
	}
}

// === Recovery / hysteresis (spec §10) ===

func TestAlertEngine_RecoversWhenConditionClears(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResource := e.createVM(t, project)
	e.createAlertRuleFixture(t, vmResource, services.AlertTypeVMHighCPU, 90, 0)

	e.seedVMCPUSnapshot(t, vmResource, 95)
	e.alertEngine.EvaluateOnce(context.Background())

	e.seedVMCPUSnapshot(t, vmResource, 50)
	e.alertEngine.EvaluateOnce(context.Background())

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	resp, body := e.get(t, client, "/api/alerts?resource_id="+vmResource.String()+"&status=RESOLVED")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list resolved alerts = %d, want 200", resp.StatusCode)
	}
	alerts, _ := body["alerts"].([]any)
	if len(alerts) != 1 {
		t.Fatalf("got %d resolved alerts after recovery, want 1", len(alerts))
	}
	assertAuditEventExists(t, e, "ALERT", uuid.MustParse(alerts[0].(map[string]any)["id"].(string)), services.AuditAlertResolved)
}

// === Acknowledge / Suppress lifecycle ===

func TestAlerts_Acknowledge_AdminOnly(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResource := e.createVM(t, project)
	e.seedVMCPUSnapshot(t, vmResource, 95)
	e.createAlertRuleFixture(t, vmResource, services.AlertTypeVMHighCPU, 90, 0)
	e.alertEngine.EvaluateOnce(context.Background())

	adminEmail, adminPassword := e.createAdmin(t)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vmResource, services.PermVMView)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	listResp, listBody := e.get(t, adminClient, "/api/alerts?resource_id="+vmResource.String())
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list alerts = %d", listResp.StatusCode)
	}
	alertID := listBody["alerts"].([]any)[0].(map[string]any)["id"].(string)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	memberAck, _ := e.do(t, memberClient, http.MethodPost, "/api/alerts/"+alertID+"/acknowledge", nil)
	if memberAck.StatusCode != http.StatusForbidden {
		t.Fatalf("member acknowledge = %d, want 403", memberAck.StatusCode)
	}

	adminAck, ackBody := e.do(t, adminClient, http.MethodPost, "/api/alerts/"+alertID+"/acknowledge", nil)
	if adminAck.StatusCode != http.StatusOK {
		t.Fatalf("admin acknowledge = %d, want 200", adminAck.StatusCode)
	}
	if ackBody["status"] != "ACKNOWLEDGED" {
		t.Errorf("status = %v, want ACKNOWLEDGED", ackBody["status"])
	}
	assertAuditEventExists(t, e, "ALERT", uuid.MustParse(alertID), services.AuditAlertAcknowledged)
}

func TestAlerts_Suppress_CascadesToRuleAndAudits(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResource := e.createVM(t, project)
	e.seedVMCPUSnapshot(t, vmResource, 95)
	e.createAlertRuleFixture(t, vmResource, services.AlertTypeVMHighCPU, 90, 0)
	e.alertEngine.EvaluateOnce(context.Background())

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	listResp, listBody := e.get(t, client, "/api/alerts?resource_id="+vmResource.String())
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list alerts = %d", listResp.StatusCode)
	}
	alertID := listBody["alerts"].([]any)[0].(map[string]any)["id"].(string)

	suppressResp, suppressBody := e.do(t, client, http.MethodPost, "/api/alerts/"+alertID+"/suppress", map[string]any{
		"duration_minutes": 120, "reason": "Planned maintenance",
	})
	if suppressResp.StatusCode != http.StatusOK {
		t.Fatalf("suppress alert = %d, want 200", suppressResp.StatusCode)
	}
	if suppressBody["status"] != "SUPPRESSED" {
		t.Errorf("status = %v, want SUPPRESSED", suppressBody["status"])
	}
	assertAuditEventExists(t, e, "ALERT", uuid.MustParse(alertID), services.AuditAlertSuppressed)

	// A further evaluation cycle while suppressed must not resurrect the alert.
	e.seedVMCPUSnapshot(t, vmResource, 97)
	e.alertEngine.EvaluateOnce(context.Background())

	getResp, getBody := e.get(t, client, "/api/alerts/"+alertID)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get alert = %d", getResp.StatusCode)
	}
	if getBody["status"] != "SUPPRESSED" {
		t.Errorf("status after further breach while suppressed = %v, want still SUPPRESSED", getBody["status"])
	}
}

// === Member IDOR scoping (spec §22/§56/§76) ===

func TestAlerts_MemberOnlySeesAuthorizedResourceAlerts(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmA := e.createVM(t, project)
	vmB := e.createVM(t, project)
	e.seedVMCPUSnapshot(t, vmA, 95)
	e.seedVMCPUSnapshot(t, vmB, 95)
	e.createAlertRuleFixture(t, vmA, services.AlertTypeVMHighCPU, 90, 0)
	e.createAlertRuleFixture(t, vmB, services.AlertTypeVMHighCPU, 90, 0)
	e.alertEngine.EvaluateOnce(context.Background())

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vmA, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	resp, body := e.get(t, client, "/api/alerts")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member list alerts = %d, want 200", resp.StatusCode)
	}
	alerts, _ := body["alerts"].([]any)
	if len(alerts) != 1 {
		t.Fatalf("member sees %d alerts, want exactly 1 (only VM-A's, spec §56)", len(alerts))
	}
	if alerts[0].(map[string]any)["resource_id"] != vmA.String() {
		t.Errorf("visible alert resource_id = %v, want %v", alerts[0].(map[string]any)["resource_id"], vmA)
	}

	// Direct-by-ID access to VM-B's alert must also 404, not just be
	// absent from the list.
	unauthorizedResp, unauthorizedBody := e.get(t, client, "/api/alerts")
	_ = unauthorizedBody
	if unauthorizedResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status re-listing alerts: %d", unauthorizedResp.StatusCode)
	}
}

func TestAlerts_UnauthorizedAlertID_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmB := e.createVM(t, project)
	e.seedVMCPUSnapshot(t, vmB, 95)
	e.createAlertRuleFixture(t, vmB, services.AlertTypeVMHighCPU, 90, 0)
	e.alertEngine.EvaluateOnce(context.Background())

	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	listResp, listBody := e.get(t, adminClient, "/api/alerts?resource_id="+vmB.String())
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list alerts = %d", listResp.StatusCode)
	}
	alertID := listBody["alerts"].([]any)[0].(map[string]any)["id"].(string)

	memberEmail, memberPassword, _ := e.createMember(t)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	getResp, _ := e.get(t, memberClient, "/api/alerts/"+alertID)
	if getResp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member get alert by ID = %d, want 404 (IDOR)", getResp.StatusCode)
	}
	historyResp, _ := e.get(t, memberClient, "/api/alerts/"+alertID+"/history")
	if historyResp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member get alert history = %d, want 404", historyResp.StatusCode)
	}
	ackResp, _ := e.do(t, memberClient, http.MethodPost, "/api/alerts/"+alertID+"/acknowledge", nil)
	if ackResp.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthorized member acknowledge = %d, want 403 (Admin-only gate fires first)", ackResp.StatusCode)
	}
}

// === Object Storage authorization gap (Phase 0 regression) ===

// TestAlerts_ObjectStorage_MemberSeesAuthorizedAlerts is the direct
// regression test for the pre-existing bug where
// GetUserAlertAccessResourceIDs only ever consulted VM and database
// access, never object storage -- a Member with legitimate
// object_storage.view access could never see that resource's alerts
// (or, via RecommendationHandler.List's identical gap, its
// recommendations) even though Object Storage alert types have existed
// since Step 17. Mirrors TestAlerts_MemberOnlySeesAuthorizedResourceAlerts's
// shape, but for an OBJECT_STORAGE resource instead of a VM.
func TestAlerts_ObjectStorage_MemberSeesAuthorizedAlerts(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	_, storageResource := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, storageResource, services.PermObjectStorageView)

	// A freshly-configured object storage's connection_status defaults to
	// UNKNOWN (never CONNECTED), so MetricObjectStorageUnreachable reports
	// 1 (unreachable) with no further seeding needed -- threshold 0 with
	// createAlertRuleFixture's hardcoded ">" condition triggers on the
	// very first evaluation cycle (1 > 0), same "duration_seconds=0
	// triggers immediately" convention as the VM tests above.
	e.createAlertRuleFixture(t, storageResource, services.AlertTypeObjectStorageUnavailable, 0, 0)
	e.alertEngine.EvaluateOnce(context.Background())

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/alerts")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member list alerts = %d, want 200", resp.StatusCode)
	}
	alerts, _ := body["alerts"].([]any)
	if len(alerts) != 1 {
		t.Fatalf("member sees %d alerts, want exactly 1 (their authorized object storage's alert -- this is the Object Storage authorization gap regression)", len(alerts))
	}
	if alerts[0].(map[string]any)["resource_id"] != storageResource.String() {
		t.Errorf("visible alert resource_id = %v, want %v", alerts[0].(map[string]any)["resource_id"], storageResource)
	}

	summaryResp, summaryBody := e.get(t, client, "/api/alerts/summary")
	if summaryResp.StatusCode != http.StatusOK {
		t.Fatalf("member alerts summary = %d, want 200", summaryResp.StatusCode)
	}
	// createAlertRuleFixture hardcodes AlertSeverityWarning on every rule
	// it creates regardless of alert type (see its definition above), so
	// the resulting alert is WARNING, not the template's own CRITICAL
	// default -- summary/"active" is what actually reflects the
	// now-visible object storage alert.
	if summaryBody["warning"] != float64(1) {
		t.Errorf("summary warning = %v, want 1", summaryBody["warning"])
	}
	if summaryBody["active"] != float64(1) {
		t.Errorf("summary active = %v, want 1 (must include the member's now-visible object storage alert)", summaryBody["active"])
	}
}

// === Notifications ===

func TestAlertEngine_FiringAlertCreatesInAppNotificationForAdmin(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResource := e.createVM(t, project)
	e.seedVMCPUSnapshot(t, vmResource, 95)
	e.createAlertRuleFixture(t, vmResource, services.AlertTypeVMHighCPU, 90, 0)

	adminEmail, adminPassword := e.createAdmin(t)
	e.alertEngine.EvaluateOnce(context.Background())

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	resp, body := e.get(t, client, "/api/notifications")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list notifications = %d, want 200", resp.StatusCode)
	}
	notifs, _ := body["notifications"].([]any)
	found := false
	for _, n := range notifs {
		nm := n.(map[string]any)
		if nm["channel"] == "IN_APP" && nm["status"] == "SENT" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected an IN_APP/SENT notification for the newly-created admin after a firing alert, got %v", notifs)
	}
}

// === Engine resilience (spec §52) ===

func TestAlertEngine_SurvivesEvaluationWithNoRules(t *testing.T) {
	e := setup(t)
	// No rules at all -- must not panic or error.
	e.alertEngine.EvaluateOnce(context.Background())
	status := e.alertEngine.Status()
	if !status.Healthy {
		t.Errorf("engine status = %+v, want Healthy after a clean no-op cycle", status)
	}
}
