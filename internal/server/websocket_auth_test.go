// This file closes a genuine coverage gap found during Step 18's polish
// pass: neither of this project's two WebSocket endpoints (the Docker
// container stats stream, internal/handlers/docker_stream.go, and the
// alerts stream, AlertsHandler.Stream in internal/handlers/alerts.go) had
// ANY dedicated test anywhere in this codebase prior to this file --
// `grep -rl websocket internal/server/*_test.go` matched nothing. The
// Step 17-era survey that fed the Step 18 plan concluded the
// *implementation* was already correct (pre-upgrade authorization, then
// CheckOrigin, matching REST exactly), which reading docker_stream.go and
// alerts.go's Stream method directly confirms -- but "the code looks
// right" and "a test proves it" are different claims, and the plan
// explicitly calls for closing that gap in this phase.
//
// Both streams are exercised the same way: gorilla/websocket's Dialer
// performs a real HTTP handshake and, on any non-101 response, returns the
// real *http.Response (with its status code) alongside ErrBadHandshake --
// exactly what's needed to assert the pre-upgrade rejection status without
// needing a full duplex connection. The session cookie set by a normal
// e.login is reused via Dialer.Jar (gorilla itself downgrades ws:// to
// http:// / wss:// to https:// before consulting the jar, so the cookie
// set during login over plain HTTP is found correctly).
package server_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"vmcontrolcenter/backend/internal/services"
)

// wsURL rewrites this test server's http:// base URL to ws://, the scheme
// gorilla/websocket's Dialer expects.
func wsURL(httpBaseURL, path string) string {
	return strings.Replace(httpBaseURL, "http://", "ws://", 1) + path
}

// dialerFor builds a Dialer sharing client's cookie jar (so the session
// established by e.login is presented on the WebSocket handshake) with a
// bounded handshake timeout so a hung authorization/upgrade path fails the
// test instead of the whole suite.
func dialerFor(client *http.Client) *websocket.Dialer {
	return &websocket.Dialer{Jar: client.Jar, HandshakeTimeout: 5 * time.Second}
}

const testFrontendOrigin = "http://localhost:3000" // matches router_test.go setup()'s FrontendOrigin

// === Docker container stats stream ===
// GET /api/vms/:id/docker/containers/:containerId/stats/stream

func TestDockerStream_UnauthorizedMember_PreUpgrade404(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	containerID := e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	url := wsURL(e.baseURL, "/api/vms/"+vm.String()+"/docker/containers/"+containerID.String()+"/stats/stream")
	_, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err == nil {
		t.Fatal("expected handshake to fail for an unauthorized member, got a successful upgrade")
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member docker stream handshake status = %v, want 404 (authorizeVMView must reject before any upgrade attempt, same as every other VM-scoped endpoint)", statusOf(resp))
	}
}

func TestDockerStream_AuthorizedMember_ForeignOrigin_Forbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	containerID := e.createDockerContainerFixture(t, vm, "web-1", "b2c3d4e5f6a1")
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	url := wsURL(e.baseURL, "/api/vms/"+vm.String()+"/docker/containers/"+containerID.String()+"/stats/stream")
	_, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {"http://evil.example.com"}})
	if err == nil {
		t.Fatal("expected handshake to be rejected for a foreign Origin, got a successful upgrade")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign-origin docker stream handshake status = %v, want 403 (CheckOrigin must reject cross-site WebSocket hijacking)", statusOf(resp))
	}
}

// TestDockerStream_AuthorizedMember_SameOrigin_UpgradeSucceeds is the
// positive-path regression check: proves the two rejection paths above
// don't also block a legitimate, authorized, same-origin caller.
func TestDockerStream_AuthorizedMember_SameOrigin_UpgradeSucceeds(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	containerID := e.createDockerContainerFixture(t, vm, "web-1", "c3d4e5f6a1b2")
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	url := wsURL(e.baseURL, "/api/vms/"+vm.String()+"/docker/containers/"+containerID.String()+"/stats/stream")
	conn, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err != nil {
		t.Fatalf("authorized same-origin docker stream handshake failed (status %v): %v", statusOf(resp), err)
	}
	defer conn.Close()

	var frame map[string]any
	if err := conn.ReadJSON(&frame); err != nil {
		t.Fatalf("read first frame: %v", err)
	}
	if frame["type"] != "waiting" {
		t.Errorf("first frame type = %v, want waiting (no metrics collected yet for this fixture container)", frame["type"])
	}
}

// === Alerts stream ===
// GET /api/alerts/stream

func TestAlertsStream_Unauthenticated_PreUpgrade401(t *testing.T) {
	e := setup(t)
	client := newClient() // never logged in

	url := wsURL(e.baseURL, "/api/alerts/stream")
	_, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err == nil {
		t.Fatal("expected handshake to fail for an unauthenticated caller, got a successful upgrade")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated alerts stream handshake status = %v, want 401", statusOf(resp))
	}
}

func TestAlertsStream_Authenticated_ForeignOrigin_Forbidden(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	url := wsURL(e.baseURL, "/api/alerts/stream")
	_, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {"http://evil.example.com"}})
	if err == nil {
		t.Fatal("expected handshake to be rejected for a foreign Origin, got a successful upgrade")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign-origin alerts stream handshake status = %v, want 403 (CheckOrigin must reject cross-site WebSocket hijacking)", statusOf(resp))
	}
}

// TestAlertsStream_Authenticated_SameOrigin_UpgradeSucceeds is the
// positive-path regression check for the alerts stream, mirroring the
// Docker stream's equivalent test above.
func TestAlertsStream_Authenticated_SameOrigin_UpgradeSucceeds(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	url := wsURL(e.baseURL, "/api/alerts/stream")
	conn, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err != nil {
		t.Fatalf("authenticated same-origin alerts stream handshake failed (status %v): %v", statusOf(resp), err)
	}
	defer conn.Close()

	var frame map[string]any
	if err := conn.ReadJSON(&frame); err != nil {
		t.Fatalf("read first frame: %v", err)
	}
	if frame["type"] != "alerts" {
		t.Errorf("first frame type = %v, want alerts", frame["type"])
	}
}

// statusOf safely reports a possibly-nil *http.Response's status code for
// error messages (Dial can return a nil response on a lower-level failure,
// e.g. connection refused, distinct from a well-formed HTTP rejection).
func statusOf(resp *http.Response) any {
	if resp == nil {
		return "<no response>"
	}
	return resp.StatusCode
}
