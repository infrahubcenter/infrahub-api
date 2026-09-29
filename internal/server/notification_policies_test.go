// This file locks in that a notification policy's three webhook-style
// destinations (generic WEBHOOK, Slack, Teams -- see
// services/notification_provider.go) actually round-trip through the real
// HTTP Create/Update endpoints, catching any wiring mismatch (sqlc param
// order, JSON tags) between the handler, service, and generated queries
// that a compile alone wouldn't surface.
package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/services"
)

func TestNotificationPolicy_CreateUpdate_RoundTripsAllWebhookURLs(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	createResp, createBody := e.do(t, client, http.MethodPost, "/api/notification-policies", map[string]any{
		"name":              "All Channels",
		"info_channels":     []string{"IN_APP"},
		"warning_channels":  []string{"IN_APP", "EMAIL"},
		"critical_channels": []string{"IN_APP", "EMAIL", "SLACK", "TEAMS", "WEBHOOK"},
		"webhook_url":       "https://hooks.example.com/generic",
		"slack_webhook_url": "https://hooks.slack.com/services/T000/B000/xxx",
		"teams_webhook_url": "https://outlook.office.com/webhook/xxx",
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create policy = %d, want 201: %v", createResp.StatusCode, createBody)
	}
	if createBody["webhook_url"] != "https://hooks.example.com/generic" {
		t.Errorf("expected webhook_url to round-trip, got %v", createBody["webhook_url"])
	}
	if createBody["slack_webhook_url"] != "https://hooks.slack.com/services/T000/B000/xxx" {
		t.Errorf("expected slack_webhook_url to round-trip, got %v", createBody["slack_webhook_url"])
	}
	if createBody["teams_webhook_url"] != "https://outlook.office.com/webhook/xxx" {
		t.Errorf("expected teams_webhook_url to round-trip, got %v", createBody["teams_webhook_url"])
	}
	policyID, _ := createBody["id"].(string)
	if policyID == "" {
		t.Fatal("expected a non-empty policy id")
	}
	// This hits the real dev database (no per-test transaction rollback in
	// this suite) -- clean up so repeated runs don't pile up junk policies
	// an admin would see cluttering the real Settings page.
	t.Cleanup(func() {
		_, _ = e.do(t, client, http.MethodDelete, "/api/notification-policies/"+policyID, nil)
	})

	updateResp, updateBody := e.do(t, client, http.MethodPut, "/api/notification-policies/"+policyID, map[string]any{
		"name":              "All Channels",
		"info_channels":     []string{},
		"warning_channels":  []string{"IN_APP"},
		"critical_channels": []string{"IN_APP"},
		"slack_webhook_url": "https://hooks.slack.com/services/T111/B111/yyy",
		"teams_webhook_url": "",
	})
	if updateResp.StatusCode != http.StatusOK {
		t.Fatalf("update policy = %d, want 200: %v", updateResp.StatusCode, updateBody)
	}
	if updateBody["slack_webhook_url"] != "https://hooks.slack.com/services/T111/B111/yyy" {
		t.Errorf("expected updated slack_webhook_url to round-trip, got %v", updateBody["slack_webhook_url"])
	}
	if _, present := updateBody["teams_webhook_url"]; present {
		t.Errorf("expected teams_webhook_url to be cleared (omitted), got %v", updateBody["teams_webhook_url"])
	}
}

func TestNotificationPolicy_SendTest_SlackAndWebhookDeliverRealRequests(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	var receivedSlack, receivedWebhook bool
	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSlack = true
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedWebhook = true
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookServer.Close()

	// Seeded directly via the store, bypassing validateWebhookURL's
	// (correct) rejection of loopback addresses -- httptest.Server only
	// ever listens on 127.0.0.1, so it can never pass through the real
	// Create/Update endpoint's SSRF hardening. What's under test here is
	// SendTest actually POSTing to these URLs, not the URL validation
	// itself (that's covered by TestNotificationPolicy_InvalidSlackWebhookURL_Rejected).
	policy, err := e.store.CreateNotificationPolicy(context.Background(), generated.CreateNotificationPolicyParams{
		Name: "Test Send Policy", InfoChannels: []string{}, WarningChannels: []string{},
		CriticalChannels: []string{"SLACK", "WEBHOOK"},
		WebhookUrl:       pgutil.Text(webhookServer.URL), SlackWebhookUrl: pgutil.Text(slackServer.URL),
	})
	if err != nil {
		t.Fatalf("seed notification policy fixture: %v", err)
	}
	policyID := policy.ID.String()
	t.Cleanup(func() {
		_, _ = e.do(t, client, http.MethodDelete, "/api/notification-policies/"+policyID, nil)
	})

	slackResp, slackBody := e.do(t, client, http.MethodPost, "/api/notification-policies/"+policyID+"/test", map[string]string{"channel": "SLACK"})
	if slackResp.StatusCode != http.StatusOK || slackBody["status"] != "sent" {
		t.Fatalf("send test SLACK = %d %v, want 200 status=sent", slackResp.StatusCode, slackBody)
	}
	if !receivedSlack {
		t.Error("expected the fake Slack server to actually receive a request")
	}

	webhookResp, webhookBody := e.do(t, client, http.MethodPost, "/api/notification-policies/"+policyID+"/test", map[string]string{"channel": "WEBHOOK"})
	if webhookResp.StatusCode != http.StatusOK || webhookBody["status"] != "sent" {
		t.Fatalf("send test WEBHOOK = %d %v, want 200 status=sent", webhookResp.StatusCode, webhookBody)
	}
	if !receivedWebhook {
		t.Error("expected the fake webhook server to actually receive a request")
	}

	// TEAMS has no URL configured on this policy -- expect a clean
	// structured failure, never a 500.
	teamsResp, teamsBody := e.do(t, client, http.MethodPost, "/api/notification-policies/"+policyID+"/test", map[string]string{"channel": "TEAMS"})
	if teamsResp.StatusCode != http.StatusOK || teamsBody["status"] != "failed" {
		t.Fatalf("send test TEAMS (unconfigured) = %d %v, want 200 status=failed", teamsResp.StatusCode, teamsBody)
	}

	assertAuditEventExists(t, e, "NOTIFICATION_POLICY", uuid.MustParse(policyID), services.AuditNotificationTestSent)
}

func TestNotificationPolicy_InvalidSlackWebhookURL_Rejected(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/notification-policies", map[string]any{
		"name":              "Bad Slack URL",
		"info_channels":     []string{},
		"warning_channels":  []string{},
		"critical_channels": []string{"SLACK"},
		"slack_webhook_url": "http://169.254.169.254/latest/meta-data/",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("create policy with link-local slack_webhook_url = %d, want 400: %v", resp.StatusCode, body)
	}
}
