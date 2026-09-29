// This file exercises the named, reusable SSH key credential HTTP surface
// (POST/GET /api/ssh-key-credentials, GET/PATCH/DELETE .../{id}) added by
// the VM section rebuild: admin-only enforcement, encryption at rest, the
// API never returning key material, invalid/passphrase-protected key
// rejection, duplicate-name handling, and the delete-blocked-while-in-use
// guard. Attaching a credential to a VM is covered separately in
// ssh_test.go.
package server_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/services"
)

func TestSSHKeyCredential_CreateAsAdmin_MemberForbidden(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	adminEmail, adminPassword := e.createAdmin(t)
	memberEmail, memberPassword, _ := e.createMember(t)
	key, _ := generateTestSSHKeyPEM(t)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	memberResp, _ := e.do(t, memberClient, http.MethodPost, "/api/ssh-key-credentials", map[string]string{
		"workspace_id": workspace.String(), "name": "prod-fleet-key", "private_key": key,
	})
	if memberResp.StatusCode != http.StatusForbidden {
		t.Fatalf("member create ssh key credential = %d, want 403", memberResp.StatusCode)
	}

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	adminResp, adminBody := e.do(t, adminClient, http.MethodPost, "/api/ssh-key-credentials", map[string]string{
		"workspace_id": workspace.String(), "name": "prod-fleet-key", "private_key": key,
	})
	if adminResp.StatusCode != http.StatusCreated {
		t.Fatalf("admin create ssh key credential = %d, want 201", adminResp.StatusCode)
	}
	if adminBody["name"] != "prod-fleet-key" {
		t.Errorf("name = %v, want prod-fleet-key", adminBody["name"])
	}
	if adminBody["fingerprint"] == nil || adminBody["fingerprint"] == "" {
		t.Error("expected a non-empty fingerprint")
	}
	if adminBody["in_use_count"] != float64(0) {
		t.Errorf("in_use_count for a freshly created credential = %v, want 0", adminBody["in_use_count"])
	}
}

// TestSSHKeyCredential_APINeverReturnsKey is a direct assertion of the
// core security requirement carried over from the legacy credential model:
// no response body, at any point in the create/list/get lifecycle, may
// contain the private key.
func TestSSHKeyCredential_APINeverReturnsKey(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	adminEmail, adminPassword := e.createAdmin(t)
	key, _ := generateTestSSHKeyPEM(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	createResp, createBody := e.do(t, client, http.MethodPost, "/api/ssh-key-credentials", map[string]string{
		"workspace_id": workspace.String(), "name": "prod-fleet-key", "private_key": key,
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d, want 201", createResp.StatusCode)
	}
	assertNoKeyMaterial(t, "create response", createBody, key)

	listResp, listBody := e.get(t, client, "/api/ssh-key-credentials?workspace_id="+workspace.String())
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list = %d, want 200", listResp.StatusCode)
	}
	assertNoKeyMaterial(t, "list response", listBody, key)

	id, _ := createBody["id"].(string)
	getResp, getBody := e.get(t, client, "/api/ssh-key-credentials/"+id)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get = %d, want 200", getResp.StatusCode)
	}
	assertNoKeyMaterial(t, "get response", getBody, key)
}

// TestSSHKeyCredential_EncryptedAtRest queries the ssh_key_credentials
// table directly (bypassing the API entirely) and confirms the stored
// bytes are neither the plaintext key nor anything containing its PEM
// markers or key material -- only SSHKeyCredentialService.GetSigner may
// ever decrypt it.
func TestSSHKeyCredential_EncryptedAtRest(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	adminEmail, adminPassword := e.createAdmin(t)
	key, pub := generateTestSSHKeyPEM(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	resp, body := e.do(t, client, http.MethodPost, "/api/ssh-key-credentials", map[string]string{
		"workspace_id": workspace.String(), "name": "prod-fleet-key", "private_key": key,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d, want 201", resp.StatusCode)
	}
	id, _ := body["id"].(string)

	row, err := e.store.GetSSHKeyCredentialByID(context.Background(), mustParseUUID(t, id))
	if err != nil {
		t.Fatalf("load stored credential row: %v", err)
	}
	stored := string(row.EncryptedPrivateKey)
	assertNoKeyMaterial(t, "stored ssh_key_credentials.encrypted_private_key", stored, key)

	// GetSigner is the ONLY decrypt path, and it must still round-trip
	// correctly -- this isn't just "encrypted", it must still be usable.
	signer, err := e.sshKeyCredentials.GetSigner(context.Background(), row.ID)
	if err != nil {
		t.Fatalf("GetSigner: %v", err)
	}
	if string(signer.PublicKey().Marshal()) != string(pub.Marshal()) {
		t.Error("GetSigner returned a key that doesn't match the stored credential's key")
	}
}

func TestSSHKeyCredential_InvalidKeyRejected(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/ssh-key-credentials", map[string]string{
		"workspace_id": workspace.String(), "name": "prod-fleet-key", "private_key": "not a key at all",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid key status = %d, want 400", resp.StatusCode)
	}
	if body["error"] == nil {
		t.Error("expected an error message for an invalid key")
	}

	creds, err := e.sshKeyCredentials.List(context.Background(), workspace)
	if err != nil {
		t.Fatalf("list ssh key credentials: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("an invalid key must not be stored, found %d credential(s)", len(creds))
	}
}

func TestSSHKeyCredential_PassphraseProtectedKeyRejected(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	adminEmail, adminPassword := e.createAdmin(t)
	key := generateTestPassphraseProtectedSSHKeyPEM(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/ssh-key-credentials", map[string]string{
		"workspace_id": workspace.String(), "name": "prod-fleet-key", "private_key": key,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("passphrase-protected key status = %d, want 400", resp.StatusCode)
	}
	if body["error"] != "passphrase-protected SSH keys are not currently supported" {
		t.Errorf("error = %v, want the documented clear rejection message", body["error"])
	}
}

func TestSSHKeyCredential_DuplicateNameInWorkspace_Conflict(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	adminEmail, adminPassword := e.createAdmin(t)
	firstKey, _ := generateTestSSHKeyPEM(t)
	secondKey, _ := generateTestSSHKeyPEM(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	first, _ := e.do(t, client, http.MethodPost, "/api/ssh-key-credentials", map[string]string{
		"workspace_id": workspace.String(), "name": "prod-fleet-key", "private_key": firstKey,
	})
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first create = %d, want 201", first.StatusCode)
	}

	second, secondBody := e.do(t, client, http.MethodPost, "/api/ssh-key-credentials", map[string]string{
		"workspace_id": workspace.String(), "name": "prod-fleet-key", "private_key": secondKey,
	})
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate name create = %d, want 409", second.StatusCode)
	}
	if secondBody["error"] == nil {
		t.Error("expected an error message for a duplicate name")
	}
}

func TestSSHKeyCredential_Rename(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	adminEmail, adminPassword := e.createAdmin(t)
	key, _ := generateTestSSHKeyPEM(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	createResp, createBody := e.do(t, client, http.MethodPost, "/api/ssh-key-credentials", map[string]string{
		"workspace_id": workspace.String(), "name": "prod-fleet-key", "private_key": key,
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d, want 201", createResp.StatusCode)
	}
	id, _ := createBody["id"].(string)

	renameResp, renameBody := e.do(t, client, http.MethodPatch, "/api/ssh-key-credentials/"+id, map[string]string{"name": "renamed-key"})
	if renameResp.StatusCode != http.StatusOK {
		t.Fatalf("rename = %d, want 200", renameResp.StatusCode)
	}
	if renameBody["name"] != "renamed-key" {
		t.Errorf("name after rename = %v, want renamed-key", renameBody["name"])
	}
}

// TestSSHKeyCredential_Delete_BlockedWhileInUse proves the delete-blocked-
// while-in-use guard (mirrors WorkspaceService.Delete's precedent): a
// credential still attached to a VM must not be deletable, and must become
// deletable again once detached.
func TestSSHKeyCredential_Delete_BlockedWhileInUse(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	vm := e.createVM(t, workspace)
	adminEmail, adminPassword := e.createAdmin(t)
	key, _ := generateTestSSHKeyPEM(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	credID := e.attachSSHKeyCredential(t, workspace, vm, key)

	blockedResp, blockedBody := e.do(t, client, http.MethodDelete, "/api/ssh-key-credentials/"+credID.String(), nil)
	if blockedResp.StatusCode != http.StatusConflict {
		t.Fatalf("delete while in use = %d, want 409", blockedResp.StatusCode)
	}
	if blockedBody["error"] == nil {
		t.Error("expected an error message explaining the credential is still in use")
	}

	detachResp, _ := e.do(t, client, http.MethodPatch, "/api/vms/"+vm.String(), map[string]string{"ssh_key_credential_id": ""})
	if detachResp.StatusCode != http.StatusOK {
		t.Fatalf("detach = %d, want 200", detachResp.StatusCode)
	}

	okResp, _ := e.do(t, client, http.MethodDelete, "/api/ssh-key-credentials/"+credID.String(), nil)
	if okResp.StatusCode != http.StatusOK {
		t.Fatalf("delete after detach = %d, want 200", okResp.StatusCode)
	}

	if _, err := e.store.GetSSHKeyCredentialByID(context.Background(), credID); err == nil {
		t.Error("expected the credential row to be gone after delete")
	}
}

func TestAudit_SSHKeyCredentialLifecycleEventsRecorded(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	adminEmail, adminPassword := e.createAdmin(t)
	key, _ := generateTestSSHKeyPEM(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	createResp, createBody := e.do(t, client, http.MethodPost, "/api/ssh-key-credentials", map[string]string{
		"workspace_id": workspace.String(), "name": "prod-fleet-key", "private_key": key,
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d, want 201", createResp.StatusCode)
	}
	id, _ := createBody["id"].(string)
	credID := mustParseUUID(t, id)

	assertAuditEventExists(t, e, "SSH_KEY_CREDENTIAL", credID, services.AuditSSHKeyCredentialCreated)

	e.do(t, client, http.MethodPatch, "/api/ssh-key-credentials/"+id, map[string]string{"name": "renamed-key"})
	assertAuditEventExists(t, e, "SSH_KEY_CREDENTIAL", credID, services.AuditSSHKeyCredentialRenamed)

	e.do(t, client, http.MethodDelete, "/api/ssh-key-credentials/"+id, nil)
	assertAuditEventExists(t, e, "SSH_KEY_CREDENTIAL", credID, services.AuditSSHKeyCredentialDeleted)
}

// === helpers ===

func mustParseUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("parse uuid %q: %v", s, err)
	}
	return id
}

// assertNoKeyMaterial fails the test if body (a decoded JSON response, or
// any other value) contains the PEM markers or any sufficiently long
// substring of the given key -- the strongest practical guarantee, in a
// black-box test, that a value never leaked into a response or storage
// column. body is stringified with %v, which recurses through
// map[string]any exactly like the decoded JSON responses this file passes
// in, so a leaked value nested anywhere in the body is still caught.
func assertNoKeyMaterial(t *testing.T, label string, body any, key string) {
	t.Helper()
	haystack := fmt.Sprintf("%v", body)
	if strings.Contains(haystack, "PRIVATE KEY") {
		t.Errorf("%s contains a PEM private-key marker", label)
	}
	for _, line := range strings.Split(key, "\n") {
		line = strings.TrimSpace(line)
		// Body lines of an OpenSSH PEM are long base64 chunks; a match on
		// any one of them proves raw key bytes leaked.
		if len(line) >= 40 && strings.Contains(haystack, line) {
			t.Errorf("%s contains a raw key body line", label)
		}
	}
}
