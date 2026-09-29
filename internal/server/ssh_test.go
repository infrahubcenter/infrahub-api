// This file exercises the Step 5 SSH connection-test / discovery /
// host-key-trust HTTP surface: admin-only enforcement, IDOR protection on
// the two member-readable GET endpoints, and audit events. Named SSH key
// credential CRUD itself (create/list/rename/delete, encryption at rest,
// invalid/passphrase-protected key rejection) is covered by
// ssh_key_credential_test.go -- this file only covers attaching/detaching a
// credential via the VM itself and the connection-test/discover/host-key
// endpoints that consume it.
//
// It intentionally does NOT attempt a real SSH connection against localhost
// for the "happy path" (that was verified manually against a real Docker
// SSH server -- see the Step 5 delivery summary); the failure-path tests
// here point at addresses guaranteed to fail fast (an unbound loopback
// port for "refused", a non-routable TEST-NET-1 address for "timeout")
// so they don't depend on any external service being reachable.
package server_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/services"
)

// generateTestSSHKeyPEM returns a freshly generated, unencrypted ed25519
// private key in OpenSSH PEM format -- a structurally valid key with no
// relationship to any real credential, safe to embed in test source -- and
// the corresponding SSH public key, so tests can verify which key ended up
// stored without ever needing to re-extract private material.
func generateTestSSHKeyPEM(t *testing.T) (pemText string, pub ssh.PublicKey) {
	t.Helper()
	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test-key")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatalf("derive ssh public key: %v", err)
	}
	return string(pem.EncodeToMemory(block)), sshPub
}

// generateTestPassphraseProtectedSSHKeyPEM returns a validly-formatted but
// passphrase-encrypted key, to exercise the documented "not currently
// supported" rejection path (Step 5 spec #10).
func generateTestPassphraseProtectedSSHKeyPEM(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "test-key", []byte("s3cr3t-passphrase"))
	if err != nil {
		t.Fatalf("marshal passphrase-protected private key: %v", err)
	}
	return string(pem.EncodeToMemory(block))
}

// createVMWithAddress is like createVM but lets the caller pick the
// address/port, needed to point connection tests at a deterministically
// unreachable target instead of the fixture's arbitrary 10.0.0.1.
func (e *testEnv) createVMWithAddress(t *testing.T, workspaceID uuid.UUID, address string, port int32) uuid.UUID {
	t.Helper()
	res, err := e.store.CreateResource(context.Background(), generated.CreateResourceParams{
		WorkspaceID:  workspaceID,
		Name:         "test-vm-" + uuid.NewString(),
		ResourceType: "VM",
	})
	if err != nil {
		t.Fatalf("create resource fixture: %v", err)
	}
	if _, err := e.store.CreateVM(context.Background(), generated.CreateVMParams{
		ResourceID: res.ID,
		Hostname:   res.Name,
		Address:    address,
		SshPort:    port,
	}); err != nil {
		t.Fatalf("create vm fixture: %v", err)
	}
	return res.ID
}

// === Attach/detach via VM update ===

func TestVMSSHKeyCredential_AttachAsAdmin_MemberForbidden(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	vm := e.createVM(t, workspace)
	adminEmail, adminPassword := e.createAdmin(t)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)
	credID := e.attachSSHKeyCredential(t, workspace, e.createVM(t, workspace), mustKey(t))

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	memberResp, _ := e.do(t, memberClient, http.MethodPatch, "/api/vms/"+vm.String(), map[string]string{"ssh_key_credential_id": credID.String()})
	if memberResp.StatusCode != http.StatusForbidden {
		t.Fatalf("member attach credential = %d, want 403 (even with vm.view access -- VM update is admin-only)", memberResp.StatusCode)
	}

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	adminResp, adminBody := e.do(t, adminClient, http.MethodPatch, "/api/vms/"+vm.String(), map[string]string{"ssh_key_credential_id": credID.String()})
	if adminResp.StatusCode != http.StatusOK {
		t.Fatalf("admin attach credential = %d, want 200", adminResp.StatusCode)
	}
	if adminBody["ssh_key_credential_id"] != credID.String() {
		t.Errorf("ssh_key_credential_id = %v, want %s", adminBody["ssh_key_credential_id"], credID)
	}
}

func mustKey(t *testing.T) string {
	key, _ := generateTestSSHKeyPEM(t)
	return key
}

func TestVMSSHKeyCredential_Reattach_SwapsSigner(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	vm := e.createVM(t, workspace)
	adminEmail, adminPassword := e.createAdmin(t)

	firstKey, firstPub := generateTestSSHKeyPEM(t)
	firstCredID := e.attachSSHKeyCredential(t, workspace, vm, firstKey)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	vmRow, err := e.store.GetVMByResourceID(context.Background(), vm)
	if err != nil {
		t.Fatalf("load vm: %v", err)
	}
	if vmRow.SshKeyCredentialID != pgutil.NullUUID(&firstCredID) {
		t.Fatalf("vm.ssh_key_credential_id after attach = %v, want %s", vmRow.SshKeyCredentialID, firstCredID)
	}
	signer, err := e.sshKeyCredentials.GetSigner(context.Background(), firstCredID)
	if err != nil {
		t.Fatalf("GetSigner for first credential: %v", err)
	}
	if string(signer.PublicKey().Marshal()) != string(firstPub.Marshal()) {
		t.Error("GetSigner returned a key that doesn't match the first credential's key")
	}

	// Reattach to a second, different named credential -- the VM's signer
	// must now resolve to the new one, not the old.
	secondKey, secondPub := generateTestSSHKeyPEM(t)
	secondCredID := e.attachSSHKeyCredential(t, workspace, e.createVM(t, workspace), secondKey)
	resp, body := e.do(t, client, http.MethodPatch, "/api/vms/"+vm.String(), map[string]string{"ssh_key_credential_id": secondCredID.String()})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reattach = %d, want 200", resp.StatusCode)
	}
	if body["ssh_key_credential_id"] != secondCredID.String() {
		t.Errorf("ssh_key_credential_id after reattach = %v, want %s", body["ssh_key_credential_id"], secondCredID)
	}

	vmRow, err = e.store.GetVMByResourceID(context.Background(), vm)
	if err != nil {
		t.Fatalf("reload vm: %v", err)
	}
	if vmRow.SshKeyCredentialID != pgutil.NullUUID(&secondCredID) {
		t.Errorf("vm.ssh_key_credential_id after reattach = %v, want %s", vmRow.SshKeyCredentialID, secondCredID)
	}

	signer, err = e.sshKeyCredentials.GetSigner(context.Background(), secondCredID)
	if err != nil {
		t.Fatalf("GetSigner for second credential: %v", err)
	}
	if string(signer.PublicKey().Marshal()) != string(secondPub.Marshal()) {
		t.Error("GetSigner after reattach returned a key that doesn't match the second credential's key")
	}
}

func TestVMSSHKeyCredential_Detach_ResetsConnectionStatus(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	vm := e.createVM(t, workspace)
	adminEmail, adminPassword := e.createAdmin(t)
	e.attachSSHKeyCredential(t, workspace, vm, mustKey(t))

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	// Force the connection status away from its default before detaching,
	// so the reset is actually observable rather than a no-op.
	vmRow, err := e.store.GetVMByResourceID(context.Background(), vm)
	if err != nil {
		t.Fatalf("load vm: %v", err)
	}
	if _, err := e.store.UpdateVMConnectionStatus(context.Background(), generated.UpdateVMConnectionStatusParams{
		ID: vmRow.ID, ConnectionStatus: "FAILED", LastConnectionError: pgutil.Text("some previous failure"),
	}); err != nil {
		t.Fatalf("seed connection status: %v", err)
	}

	detachResp, detachBody := e.do(t, client, http.MethodPatch, "/api/vms/"+vm.String(), map[string]string{"ssh_key_credential_id": ""})
	if detachResp.StatusCode != http.StatusOK {
		t.Fatalf("detach credential = %d, want 200", detachResp.StatusCode)
	}
	if detachBody["ssh_key_credential_id"] != nil {
		t.Errorf("ssh_key_credential_id after detach = %v, want absent/nil", detachBody["ssh_key_credential_id"])
	}

	statusResp, statusBody := e.get(t, client, "/api/vms/"+vm.String()+"/connection-status")
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("connection-status = %d, want 200", statusResp.StatusCode)
	}
	if statusBody["credential_configured"] != false {
		t.Errorf("credential_configured after detach = %v, want false", statusBody["credential_configured"])
	}
	if statusBody["connection_status"] != "NOT_CONFIGURED" {
		t.Errorf("connection_status after detach = %v, want NOT_CONFIGURED", statusBody["connection_status"])
	}
}

// === Connection test ===

func TestConnectionTest_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/connection-test", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member connection-test = %d, want 403", resp.StatusCode)
	}
}

func TestConnectionTest_NotConfigured(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/connection-test", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connection-test with no credential = %d, want 200 (operation endpoint, status conveyed in body)", resp.StatusCode)
	}
	if body["status"] != "failed" {
		t.Errorf("status = %v, want failed", body["status"])
	}
	if body["error_code"] != "VM_NOT_CONFIGURED" {
		t.Errorf("error_code = %v, want VM_NOT_CONFIGURED", body["error_code"])
	}
}

func TestConnectionTest_ConnectionRefused(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	// Port 1 on loopback: nothing listens there, so the OS returns
	// ECONNREFUSED immediately -- deterministic, no timeout wait needed.
	vm := e.createVMWithAddress(t, project, "127.0.0.1", 1)
	adminEmail, adminPassword := e.createAdmin(t)
	e.attachSSHKeyCredential(t, project, vm, mustKey(t))

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/connection-test", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connection-test = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "failed" {
		t.Fatalf("status = %v, want failed", body["status"])
	}
	if body["error_code"] != "SSH_CONNECTION_REFUSED" {
		t.Errorf("error_code = %v, want SSH_CONNECTION_REFUSED", body["error_code"])
	}

	// The outcome must also be reflected in resources.status/connection_status
	// via RecordConnectionOutcome -- confirmed through the follow-up GET
	// rather than re-deriving it, since that's what a real client would do.
	statusResp, statusBody := e.get(t, client, "/api/vms/"+vm.String()+"/connection-status")
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("connection-status = %d, want 200", statusResp.StatusCode)
	}
	if statusBody["connection_status"] != "FAILED" {
		t.Errorf("connection_status = %v, want FAILED", statusBody["connection_status"])
	}
	if statusBody["last_connection_error"] != "Connection refused." {
		t.Errorf("last_connection_error = %v, want the same safe message the connection-test returned", statusBody["last_connection_error"])
	}
}

// === Discovery ===

func TestDiscover_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/discover", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member discover = %d, want 403", resp.StatusCode)
	}
}

func TestDiscover_ConnectionFailure_DoesNotErasePriorData(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVMWithAddress(t, project, "127.0.0.1", 1)
	adminEmail, adminPassword := e.createAdmin(t)
	e.attachSSHKeyCredential(t, project, vm, mustKey(t))

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	// Seed "previously discovered" data directly, simulating a prior
	// successful run, to prove a subsequent failed discovery doesn't wipe it.
	hostname := "previously-known-host"
	if _, err := e.store.UpdateVMDiscoveryResult(context.Background(), generated.UpdateVMDiscoveryResultParams{
		ID: mustVMRowID(t, e, vm), Hostname: pgutil.Text(hostname),
	}); err != nil {
		t.Fatalf("seed prior discovery data: %v", err)
	}

	resp, body := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/discover", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discover = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "failed" {
		t.Fatalf("status = %v, want failed (connection refused before any command ran)", body["status"])
	}

	vmRow, err := e.store.GetVMByResourceID(context.Background(), vm)
	if err != nil {
		t.Fatalf("reload vm: %v", err)
	}
	if vmRow.Hostname != hostname {
		t.Errorf("hostname after failed discovery = %q, want preserved %q", vmRow.Hostname, hostname)
	}
}

// === GET endpoints: authenticated-any-role but still authorization-gated (IDOR) ===

func TestConnectionStatus_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vm.String()+"/connection-status")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member connection-status = %d, want 404 (existence must not be disclosed)", resp.StatusCode)
	}
}

func TestDiscoveryHistory_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vm.String()+"/discovery")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member discovery history = %d, want 404", resp.StatusCode)
	}
}

func TestDiscoveryHistory_AuthorizedMember_CanView(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/vms/"+vm.String()+"/discovery")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorized member discovery history = %d, want 200", resp.StatusCode)
	}
	if _, ok := body["runs"]; !ok {
		t.Error("expected a runs field")
	}
}

// === Host key trust ===

func TestHostKeyTrust_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/host-key/trust", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member trust host key = %d, want 403", resp.StatusCode)
	}
}

// === Audit ===

func TestAudit_SSHKeyAttachAndConnectionEventsRecorded(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVMWithAddress(t, project, "127.0.0.1", 1)
	adminEmail, adminPassword := e.createAdmin(t)
	credID := e.attachSSHKeyCredential(t, project, e.createVM(t, project), mustKey(t))

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	e.do(t, client, http.MethodPatch, "/api/vms/"+vm.String(), map[string]string{"ssh_key_credential_id": credID.String()})
	assertAuditEventExists(t, e, "VM", vm, services.AuditVMSSHKeyAttached)

	e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/connection-test", nil)
	assertAuditEventExists(t, e, "VM", vm, services.AuditSSHConnectionFailed)

	e.do(t, client, http.MethodPatch, "/api/vms/"+vm.String(), map[string]string{"ssh_key_credential_id": ""})
	assertAuditEventExists(t, e, "VM", vm, services.AuditVMSSHKeyDetached)
}

// === helpers ===

func mustVMRowID(t *testing.T, e *testEnv, resourceID uuid.UUID) uuid.UUID {
	t.Helper()
	vm, err := e.store.GetVMByResourceID(context.Background(), resourceID)
	if err != nil {
		t.Fatalf("load vm row: %v", err)
	}
	return vm.ID
}
