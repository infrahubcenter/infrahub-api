// This file exercises the Step 8 Docker discovery/inventory/metrics HTTP
// surface: IDOR protection (a container that genuinely exists but on a
// different VM must 404, not just a container ID that doesn't exist at
// all -- spec §75), admin-only scan, member view scoping, "no fake data"
// (an unscanned VM reports an empty/unknown inventory, never a fabricated
// container list or daemon status), and the manual-scan rate limit. Like
// package_test.go, connection-dependent cases (the real scan against a
// live Docker daemon) were verified manually against a real Docker-in-
// Docker test container, documented in the Step 8 delivery summary --
// these tests write container/image/network/volume fixture rows directly
// into the database (mirroring package_test.go's
// createPackageUpdateFixture pattern) rather than driving a real scan.
package server_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/services"
)

// createDockerContainerFixture inserts a container row for vmResourceID
// directly (bypassing SSH/discovery), returning its DB row ID.
func (e *testEnv) createDockerContainerFixture(t *testing.T, vmResourceID uuid.UUID, name, dockerContainerID string) uuid.UUID {
	t.Helper()
	vm, err := e.store.GetVMByResourceID(context.Background(), vmResourceID)
	if err != nil {
		t.Fatalf("load vm for container fixture: %v", err)
	}
	row, err := e.store.UpsertDockerContainer(context.Background(), generated.UpsertDockerContainerParams{
		VmID: vm.ID, ContainerID: dockerContainerID, Name: name, Image: "nginx:1.27",
		Status: "RUNNING", State: pgutil.Text("running"), Health: pgutil.Text("NO_HEALTHCHECK"),
		Ports: []byte("[]"), Mounts: []byte("[]"),
	})
	if err != nil {
		t.Fatalf("create docker container fixture: %v", err)
	}
	return row.ID
}

// === GET /docker ===

func TestDockerOverview_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vm.String()+"/docker")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member docker overview = %d, want 404 (existence must not be disclosed)", resp.StatusCode)
	}
}

func TestDockerOverview_AuthorizedMember_UnknownInitially(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/vms/"+vm.String()+"/docker")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorized member docker overview = %d, want 200", resp.StatusCode)
	}
	if body["daemon_status"] != "UNKNOWN" {
		t.Errorf("daemon_status = %v, want UNKNOWN (never scanned yet -- must never fabricate RUNNING)", body["daemon_status"])
	}
	if _, present := body["last_scan"]; present {
		t.Error("last_scan should be absent when no scan has ever run")
	}
}

func TestDockerSummary_EmptyInitially(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/vms/"+vm.String()+"/docker/summary")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("docker summary = %d, want 200", resp.StatusCode)
	}
	for _, field := range []string{"containers_total", "containers_running", "containers_stopped", "containers_unhealthy", "images_total", "networks_total", "volumes_total"} {
		if body[field] != float64(0) {
			t.Errorf("%s = %v, want 0", field, body[field])
		}
	}
}

// === GET /docker/containers ===

func TestDockerContainers_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vm.String()+"/docker/containers")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member docker containers = %d, want 404", resp.StatusCode)
	}
}

func TestDockerContainers_AuthorizedMember_SeesFixtureContainer(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)
	e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/vms/"+vm.String()+"/docker/containers")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorized member docker containers = %d, want 200", resp.StatusCode)
	}
	containers, _ := body["containers"].([]any)
	if len(containers) != 1 {
		t.Fatalf("containers = %v, want exactly 1", containers)
	}
	first := containers[0].(map[string]any)
	if first["name"] != "web-1" {
		t.Errorf("container name = %v, want web-1", first["name"])
	}
}

// === IDOR: container-scoped endpoints (spec §75) ===

func TestDockerContainer_IDOR_ContainerFromDifferentVM_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmA := e.createVM(t, project)
	vmB := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)
	memberEmail, memberPassword, memberID := e.createMember(t)
	// Member is authorized on VM-A only.
	e.grantDirectVMAccess(t, memberID, vmA, services.PermVMView)
	// The container genuinely exists, but on VM-B.
	containerOnB := e.createDockerContainerFixture(t, vmB, "db-1", "f6e5d4c3b2a1")

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	// Sanity check: the container is real and reachable via its own VM.
	sanity, _ := e.get(t, adminClient, "/api/vms/"+vmB.String()+"/docker/containers/"+containerOnB.String())
	if sanity.StatusCode != http.StatusOK {
		t.Fatalf("precondition: admin GET container via its own VM = %d, want 200", sanity.StatusCode)
	}

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	// VM-A/container-B: a container that exists, but on a different VM.
	// Must DENY exactly like a nonexistent container ID -- not leak that
	// it exists elsewhere.
	resp, body := e.get(t, client, "/api/vms/"+vmA.String()+"/docker/containers/"+containerOnB.String())
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("VM-A/container-from-VM-B = %d, want 404 (IDOR)", resp.StatusCode)
	}
	for _, leaky := range []string{"name", "image", "status"} {
		if _, present := body[leaky]; present {
			t.Errorf("404 IDOR response leaked field %q: %v", leaky, body)
		}
	}

	// VM-B/container-B, requested by a member with no access to VM-B at
	// all: must also 404 (existence of the VM itself must not leak).
	resp2, _ := e.get(t, client, "/api/vms/"+vmB.String()+"/docker/containers/"+containerOnB.String())
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("VM-B/container-B for a member unauthorized on VM-B = %d, want 404", resp2.StatusCode)
	}
}

func TestDockerContainer_NonexistentID_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vm.String()+"/docker/containers/"+uuid.NewString())
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("nonexistent container id = %d, want 404", resp.StatusCode)
	}
}

func TestDockerContainerMetricsCurrent_IDOR_ContainerFromDifferentVM_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmA := e.createVM(t, project)
	vmB := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)
	containerOnB := e.createDockerContainerFixture(t, vmB, "cache-1", "112233445566")

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vmA.String()+"/docker/containers/"+containerOnB.String()+"/metrics/current")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("VM-A/container-from-VM-B metrics/current = %d, want 404 (IDOR)", resp.StatusCode)
	}
}

func TestDockerContainerMetricsHistory_IDOR_ContainerFromDifferentVM_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmA := e.createVM(t, project)
	vmB := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)
	containerOnB := e.createDockerContainerFixture(t, vmB, "cache-2", "223344556677")

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vmA.String()+"/docker/containers/"+containerOnB.String()+"/metrics/history")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("VM-A/container-from-VM-B metrics/history = %d, want 404 (IDOR)", resp.StatusCode)
	}
}

// === POST /docker/scan ===

func TestDockerScan_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/docker/scan", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member docker scan = %d, want 403", resp.StatusCode)
	}
}

func TestDockerScan_RateLimited(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	// First scan: will fail fast (unreachable/unconfigured SSH), but that
	// still consumes the debounce window.
	first, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/docker/scan", nil)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first scan = %d, want 200 (a connection failure is still a 200 with a FAILED body, not an HTTP error)", first.StatusCode)
	}

	second, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/docker/scan", nil)
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("immediate second scan = %d, want 429 (rate limited)", second.StatusCode)
	}
}

func TestDockerScan_AuditEventsRecorded(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/docker/scan", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("docker scan = %d, want 200", resp.StatusCode)
	}

	assertAuditEventExists(t, e, "VM", vm, services.AuditDockerScanStarted)
	// An unreachable fixture VM (no SSH configured) fails the connection,
	// so the completed event is the FAILED variant.
	assertAuditEventExists(t, e, "VM", vm, services.AuditDockerScanFailed)
}

// === GET /docker/images, /docker/networks, /docker/volumes ===

func TestDockerImages_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vm.String()+"/docker/images")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member docker images = %d, want 404", resp.StatusCode)
	}
}

func TestDockerNetworksAndVolumes_EmptyInitially(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	netResp, netBody := e.get(t, client, "/api/vms/"+vm.String()+"/docker/networks")
	if netResp.StatusCode != http.StatusOK {
		t.Fatalf("docker networks = %d, want 200", netResp.StatusCode)
	}
	if networks, _ := netBody["networks"].([]any); len(networks) != 0 {
		t.Errorf("networks = %v, want empty", networks)
	}

	volResp, volBody := e.get(t, client, "/api/vms/"+vm.String()+"/docker/volumes")
	if volResp.StatusCode != http.StatusOK {
		t.Fatalf("docker volumes = %d, want 200", volResp.StatusCode)
	}
	if volumes, _ := volBody["volumes"].([]any); len(volumes) != 0 {
		t.Errorf("volumes = %v, want empty", volumes)
	}
}

// === GET /docker/containers/:id/metrics/current -- no fake data ===

func TestDockerContainerMetricsCurrent_NoDataYet_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)
	container := e.createDockerContainerFixture(t, vm, "app-1", "aabbccddeeff")

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vm.String()+"/docker/containers/"+container.String()+"/metrics/current")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("metrics/current with no metrics ever collected = %d, want 404 (must never fabricate a sample)", resp.StatusCode)
	}
}
