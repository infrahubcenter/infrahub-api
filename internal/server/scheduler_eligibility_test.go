// This file guards a real bug the named SSH key credential rework
// (migration 051) could easily have reintroduced: every periodic
// scheduler's "which VMs are SSH-eligible" work-list query, plus the
// reboot/update-plan prechecks' HasSSHCredential gate, used to check for a
// row in the legacy per-VM credentials table. A VM created after the
// rework never has one -- it only ever gets vms.ssh_key_credential_id set
// -- so if any of these queries were left unmigrated, every new-style VM
// would silently and permanently fall out of monitoring/package/docker
// scanning and be rejected from reboot/update-plan creation, with no
// error, just an empty scheduler work list or a generic "not configured"
// rejection. These tests call the store methods directly (no HTTP, no
// scheduler loop) so they runs deterministically. They assert containment
// (a specific VM's resource ID is/isn't present) rather than exact list
// length, since these queries are intentionally global/unfiltered and
// this suite has no per-test DB isolation from fixtures other tests leave
// behind.
package server_test

import (
	"context"
	"testing"
)

func TestSchedulerEligibility_NamedCredentialVM_IsEligible_KeylessVM_IsNot(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	credentialedVM := e.createVM(t, workspace)
	keylessVM := e.createVM(t, workspace)
	e.attachSSHKeyCredential(t, workspace, credentialedVM, mustKey(t))

	ctx := context.Background()

	monitoringRows, err := e.store.ListMonitoringEnabledVMs(ctx)
	if err != nil {
		t.Fatalf("ListMonitoringEnabledVMs: %v", err)
	}
	var monitoringIDs []any
	for _, r := range monitoringRows {
		monitoringIDs = append(monitoringIDs, r.ResourceID)
	}
	assertContainsResourceID(t, "ListMonitoringEnabledVMs", monitoringIDs, credentialedVM, keylessVM)

	packageRows, err := e.store.ListPackageScanEnabledVMs(ctx)
	if err != nil {
		t.Fatalf("ListPackageScanEnabledVMs: %v", err)
	}
	var packageIDs []any
	for _, r := range packageRows {
		packageIDs = append(packageIDs, r.ResourceID)
	}
	assertContainsResourceID(t, "ListPackageScanEnabledVMs", packageIDs, credentialedVM, keylessVM)

	dockerScanRows, err := e.store.ListDockerScanEnabledVMs(ctx)
	if err != nil {
		t.Fatalf("ListDockerScanEnabledVMs: %v", err)
	}
	var dockerScanIDs []any
	for _, r := range dockerScanRows {
		dockerScanIDs = append(dockerScanIDs, r.ResourceID)
	}
	assertContainsResourceID(t, "ListDockerScanEnabledVMs", dockerScanIDs, credentialedVM, keylessVM)

	hasCredCredentialed, err := e.store.HasSSHCredential(ctx, credentialedVM)
	if err != nil {
		t.Fatalf("HasSSHCredential(credentialed): %v", err)
	}
	if !hasCredCredentialed {
		t.Error("HasSSHCredential = false for a VM with a named credential attached, want true")
	}
	hasCredKeyless, err := e.store.HasSSHCredential(ctx, keylessVM)
	if err != nil {
		t.Fatalf("HasSSHCredential(keyless): %v", err)
	}
	if hasCredKeyless {
		t.Error("HasSSHCredential = true for a keyless VM, want false")
	}

	// The reboot precheck gate funnels through HasSSHCredential -- a light
	// end-to-end confirmation that a keyless VM is correctly flagged via
	// the real API path, not just the raw query.
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	resp, body := e.do(t, client, "POST", "/api/vms/"+keylessVM.String()+"/reboot/precheck", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("reboot precheck on keyless VM = %d, want 200 (operation endpoint, failure conveyed in body)", resp.StatusCode)
	}
	if body["ready"] != false {
		t.Errorf("reboot precheck ready for a keyless VM = %v, want false", body["ready"])
	}
	checks, _ := body["checks"].([]any)
	foundSSHCheck := false
	for _, c := range checks {
		item, _ := c.(map[string]any)
		if item["name"] == "ssh_configured" {
			foundSSHCheck = true
			if item["status"] != "FAIL" {
				t.Errorf("ssh_configured check status for a keyless VM = %v, want FAIL", item["status"])
			}
		}
	}
	if !foundSSHCheck {
		t.Error("expected an ssh_configured check item in the precheck response")
	}
}

func assertContainsResourceID(t *testing.T, label string, ids []any, want, wantAbsent any) {
	t.Helper()
	foundWant, foundAbsent := false, false
	for _, id := range ids {
		if id == want {
			foundWant = true
		}
		if id == wantAbsent {
			foundAbsent = true
		}
	}
	if !foundWant {
		t.Errorf("%s: expected the credentialed VM's resource_id to be present, it was not", label)
	}
	if foundAbsent {
		t.Errorf("%s: expected the keyless VM's resource_id to be absent, it was present", label)
	}
}
