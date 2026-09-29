// This file exercises Step 21's /settings backend: personal settings
// (GET/PUT /api/me/settings, always self-service) and platform settings
// (GET /api/settings/platform, Admin-only, read-only).
package server_test

import (
	"context"
	"net/http"
	"testing"

	"vmcontrolcenter/backend/internal/services"
)

func TestMeSettings_DefaultsForNewUser(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/me/settings")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/me/settings = %d, want 200", resp.StatusCode)
	}
	if body["theme"] != "SYSTEM" {
		t.Errorf("expected default theme SYSTEM, got %v", body["theme"])
	}
	if body["timezone"] != "UTC" {
		t.Errorf("expected default timezone UTC, got %v", body["timezone"])
	}
	if body["email"] != memberEmail {
		t.Errorf("expected email %s, got %v", memberEmail, body["email"])
	}
}

func TestMeSettings_UpdateThemeAndTimezone_Persists(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.do(t, client, http.MethodPut, "/api/me/settings", map[string]any{
		"theme": "DARK", "timezone": "America/New_York", "date_format": "MM/DD/YYYY",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/me/settings = %d, want 200, body=%v", resp.StatusCode, body)
	}
	if body["theme"] != "DARK" {
		t.Errorf("expected theme DARK in response, got %v", body["theme"])
	}

	// Persistence test (spec §12: change, refresh/re-fetch, still there) --
	// a fresh GET on the same session must reflect the saved value.
	resp2, body2 := e.get(t, client, "/api/me/settings")
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/me/settings after update = %d, want 200", resp2.StatusCode)
	}
	if body2["theme"] != "DARK" || body2["timezone"] != "America/New_York" || body2["date_format"] != "MM/DD/YYYY" {
		t.Errorf("settings did not persist: %v", body2)
	}

	// Persistence across a fresh login (spec §12: logout, login again,
	// verify setting persists) -- a brand new client/session for the same
	// user must see the same saved preferences, proving they're stored
	// server-side per-user, not just client-side.
	newSessionClient := newClient()
	e.login(t, newSessionClient, memberEmail, memberPassword)
	resp3, body3 := e.get(t, newSessionClient, "/api/me/settings")
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/me/settings on new session = %d, want 200", resp3.StatusCode)
	}
	if body3["theme"] != "DARK" {
		t.Errorf("expected theme to persist across a new login session, got %v", body3["theme"])
	}
}

func TestMeSettings_InvalidTheme_Rejected(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPut, "/api/me/settings", map[string]any{"theme": "NEON"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("PUT with invalid theme = %d, want 400", resp.StatusCode)
	}
}

func TestMeSettings_InvalidTimezone_Rejected(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPut, "/api/me/settings", map[string]any{"timezone": "Not/A_Real_Zone"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("PUT with invalid timezone = %d, want 400", resp.StatusCode)
	}
}

// A user must never be able to mute CRITICAL_ALERT -- it must always still
// reach every authorized recipient (mirrors NotificationService.NotifyAlert's
// existing "Admins always receive every alert" guarantee).
func TestMeSettings_CannotMuteCriticalAlert(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPut, "/api/me/settings", map[string]any{
		"muted_notification_categories": []string{"CRITICAL_ALERT"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("PUT muting CRITICAL_ALERT = %d, want 400", resp.StatusCode)
	}
}

func TestMeSettings_UpdateName_ReusesExistingAccountService(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.do(t, client, http.MethodPut, "/api/me/settings", map[string]any{"name": "Renamed Member"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/me/settings (name) = %d, want 200", resp.StatusCode)
	}
	if body["name"] != "Renamed Member" {
		t.Errorf("expected updated name in response, got %v", body["name"])
	}

	meResp, meBody := e.get(t, client, "/api/auth/me")
	if meResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/auth/me = %d, want 200", meResp.StatusCode)
	}
	if meBody["name"] != "Renamed Member" {
		t.Errorf("expected GET /api/auth/me to reflect the new name, got %v", meBody["name"])
	}
}

// A Member's personal-settings endpoint has no user_id/target parameter at
// all -- it always acts on the caller from context -- so there is no field
// to substitute to reach another user's settings (spec §32's "Member ->
// another user's personal settings" IDOR case). This test documents that
// invariant by confirming the request body's absence of any such field
// still only ever affects the caller.
func TestMeSettings_AlwaysActsOnCallerOnly(t *testing.T) {
	e := setup(t)
	memberAEmail, memberAPassword, memberAID := e.createMember(t)
	_, _, memberBID := e.createMember(t)
	clientA := newClient()
	e.login(t, clientA, memberAEmail, memberAPassword)

	resp, _ := e.do(t, clientA, http.MethodPut, "/api/me/settings", map[string]any{"theme": "LIGHT"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/me/settings = %d, want 200", resp.StatusCode)
	}

	prefsA, err := e.userPreferences.Get(context.Background(), memberAID)
	if err != nil {
		t.Fatalf("load member A preferences: %v", err)
	}
	if prefsA.Theme != "LIGHT" {
		t.Errorf("expected member A's own theme to change, got %v", prefsA.Theme)
	}
	prefsB, err := e.userPreferences.Get(context.Background(), memberBID)
	if err != nil {
		t.Fatalf("load member B preferences: %v", err)
	}
	if prefsB.Theme != "SYSTEM" {
		t.Errorf("member B's settings must be untouched by member A's request, got %v", prefsB.Theme)
	}
}

// TestMeSettings_MutedCategorySuppressesInAppNotification proves the
// muted_notification_categories setting is a real behavior change (Step
// 21 spec: "Do not create fake settings that don't affect application
// behavior"), not a cosmetic toggle -- a Member who mutes VM_EVENT and is
// then an authorized recipient of a firing VM alert gets no IN_APP
// notification for it, while an Admin (recipient of every alert, nothing
// muted) still does for the exact same firing alert.
func TestMeSettings_MutedCategorySuppressesInAppNotification(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResource := e.createVM(t, project)
	e.seedVMCPUSnapshot(t, vmResource, 95)
	e.createAlertRuleFixture(t, vmResource, services.AlertTypeVMHighCPU, 90, 0) // Warning severity -> VM_EVENT category

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vmResource, services.PermVMView)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	muteResp, _ := e.do(t, memberClient, http.MethodPut, "/api/me/settings", map[string]any{
		"muted_notification_categories": []string{"VM_EVENT"},
	})
	if muteResp.StatusCode != http.StatusOK {
		t.Fatalf("member mute VM_EVENT = %d, want 200", muteResp.StatusCode)
	}

	adminEmail, adminPassword := e.createAdmin(t)
	e.alertEngine.EvaluateOnce(context.Background())

	memberNotifResp, memberNotifBody := e.get(t, memberClient, "/api/notifications")
	if memberNotifResp.StatusCode != http.StatusOK {
		t.Fatalf("member list notifications = %d, want 200", memberNotifResp.StatusCode)
	}
	if notifs, _ := memberNotifBody["notifications"].([]any); len(notifs) != 0 {
		t.Errorf("expected the member who muted VM_EVENT to receive 0 notifications, got %d: %v", len(notifs), notifs)
	}

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	adminNotifResp, adminNotifBody := e.get(t, adminClient, "/api/notifications")
	if adminNotifResp.StatusCode != http.StatusOK {
		t.Fatalf("admin list notifications = %d, want 200", adminNotifResp.StatusCode)
	}
	found := false
	for _, n := range adminNotifBody["notifications"].([]any) {
		nm := n.(map[string]any)
		if nm["channel"] == "IN_APP" && nm["status"] == "SENT" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected the admin (who muted nothing) to still receive the IN_APP notification for the same firing alert")
	}
}

func TestPlatformSettings_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/settings/platform")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("member GET /api/settings/platform = %d, want 403", resp.StatusCode)
	}
}

func TestPlatformSettings_Admin_ReturnsSafeConfigNoSecrets(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/settings/platform")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin GET /api/settings/platform = %d, want 200", resp.StatusCode)
	}
	if body["platform_name"] != "Infra Hub Center" {
		t.Errorf("expected platform_name 'Infra Hub Center', got %v", body["platform_name"])
	}
	for _, secretField := range []string{"database_url", "jwt_secret", "ssh_credential_encryption_key", "password"} {
		if _, present := body[secretField]; present {
			t.Errorf("platform settings response must never include %q", secretField)
		}
	}
}
