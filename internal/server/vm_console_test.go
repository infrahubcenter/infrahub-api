// This file exercises Step 22's VM Console (GET /api/vms/:id/console): the
// WebSocket-authorization gate (mirroring websocket_auth_test.go's
// pattern exactly -- unauthenticated, unauthorized, view-only-but-not-
// connect, and foreign-origin rejections, all pre-upgrade) and, using a
// minimal in-process fake SSH server, the full real plumbing end to end --
// SSH connect, PTY, Shell, input/output relay, resize, disconnect cleanup,
// and the open/close audit events -- not just "the code looks right."
package server_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/services"
)

// === fake SSH server ===
//
// A minimal in-process SSH server standing in for a real VM: it accepts
// exactly one known client public key, and its "shell" simply echoes every
// byte it receives on the channel back out prefixed with "echo:" -- enough
// to prove Console's real stdin/stdout/resize plumbing works without
// needing an actual OS shell.

type fakeSSHServer struct {
	host string
	port int
}

func startFakeSSHServer(t *testing.T, hostSigner ssh.Signer, acceptedClientKey ssh.PublicKey) *fakeSSHServer {
	t.Helper()

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(acceptedClientKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unknown public key")
		},
	}
	config.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			nConn, err := listener.Accept()
			if err != nil {
				return
			}
			go acceptFakeSSHConn(nConn, config)
		}
	}()

	host, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return &fakeSSHServer{host: host, port: port}
}

func acceptFakeSSHConn(nConn net.Conn, config *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go handleFakeSSHSession(channel, requests)
	}
}

// decodeSSHExecCommand decodes an "exec" channel request's payload (a
// uint32-length-prefixed string, per RFC 4254 §6.5) into the command text.
func decodeSSHExecCommand(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	n := binary.BigEndian.Uint32(payload[:4])
	if int(n) > len(payload)-4 {
		return ""
	}
	return string(payload[4 : 4+n])
}

func handleFakeSSHSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	for req := range requests {
		switch req.Type {
		case "pty-req", "window-change":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "shell":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			go func() {
				buf := make([]byte, 1024)
				for {
					n, err := channel.Read(buf)
					if n > 0 {
						_, _ = channel.Write([]byte("echo:"))
						_, _ = channel.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		case "exec":
			// Used by the Docker Logs tests (session.Start, not Shell). The
			// live-tail full-session test doesn't care what command was
			// requested -- it only needs to prove the exec channel + output
			// relay pipeline works, so the default response ignores the
			// command entirely. The log-capture full-session test DOES care
			// (docker_log_capture_test.go): its command contains "--since"
			// and parses a leading RFC3339Nano timestamp off each line, so
			// that one case alone gets a properly timestamped response.
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			command := decodeSSHExecCommand(req.Payload)
			go func() {
				if strings.Contains(command, "--since") {
					_, _ = channel.Write([]byte(time.Now().UTC().Format(time.RFC3339Nano) + " hello from container\n"))
				} else {
					_, _ = channel.Write([]byte("hello from container\n"))
				}
				_ = channel.CloseWrite()
				// A real server always follows exec output with an
				// exit-status reply (RFC 4254 §6.10) -- session.Run()
				// (used by services.RemoteExecutor, the log-capture path's
				// `docker logs --since` call) blocks waiting for exactly
				// this, unlike session.Start() (the live-tail path), which
				// never calls Wait() and is already tolerant of the
				// channel just closing.
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ ExitStatus uint32 }{0}))
				_ = channel.Close()
			}()
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// waitForAuditEvent polls (audit logging here happens on a goroutine racing
// the test's own WebSocket-close call) rather than asserting once, only for
// the CLOSED event -- OPENED is always already durable by the time a test
// checks it, since it's written before Console ever reads a frame.
func waitForAuditEvent(t *testing.T, e *testEnv, resourceID uuid.UUID, action string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		logs, err := e.store.ListAuditLogsByResource(context.Background(), generated.ListAuditLogsByResourceParams{
			ResourceID: pgutil.NullUUID(&resourceID), Limit: 500,
		})
		if err != nil {
			t.Fatalf("query audit logs: %v", err)
		}
		for _, l := range logs {
			if l.Action == action {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// === WebSocket authorization (mirrors websocket_auth_test.go exactly) ===

func TestVMConsole_Unauthenticated_PreUpgrade401(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	client := newClient() // never logged in

	url := wsURL(e.baseURL, "/api/vms/"+vm.String()+"/console")
	_, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err == nil {
		t.Fatal("expected handshake to fail for an unauthenticated caller, got a successful upgrade")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated console handshake status = %v, want 401", statusOf(resp))
	}
}

func TestVMConsole_UnauthorizedMember_PreUpgrade404(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, _ := e.createMember(t) // no grant at all

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	url := wsURL(e.baseURL, "/api/vms/"+vm.String()+"/console")
	_, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err == nil {
		t.Fatal("expected handshake to fail for an unauthorized member, got a successful upgrade")
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member console handshake status = %v, want 404", statusOf(resp))
	}
}

// TestVMConsole_ViewOnlyMember_PreUpgrade404 proves the specific
// separation docs/authorization.md has described since Step 3: vm.view
// does NOT imply vm.connect. A member who can see this VM's details must
// still be denied Console.
func TestVMConsole_ViewOnlyMember_PreUpgrade404(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView) // view only, NOT connect

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	url := wsURL(e.baseURL, "/api/vms/"+vm.String()+"/console")
	_, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err == nil {
		t.Fatal("expected handshake to fail for a view-only member, got a successful upgrade")
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("view-only member console handshake status = %v, want 404 (vm.view must never imply vm.connect)", statusOf(resp))
	}
}

func TestVMConsole_AuthorizedMember_ForeignOrigin_Forbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMConnect)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	url := wsURL(e.baseURL, "/api/vms/"+vm.String()+"/console")
	_, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {"http://evil.example.com"}})
	if err == nil {
		t.Fatal("expected handshake to be rejected for a foreign Origin, got a successful upgrade")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign-origin console handshake status = %v, want 403", statusOf(resp))
	}
}

// TestVMConsole_AuthorizedMember_NoSSHCredential_SafeErrorFrame proves the
// upgrade itself succeeds for an authorized caller (the positive
// authorization path), and that a VM with no SSH credential configured
// yet fails safely -- a clear, generic error frame, never a raw
// connection/library error.
func TestVMConsole_AuthorizedMember_NoSSHCredential_SafeErrorFrame(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMConnect)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	url := wsURL(e.baseURL, "/api/vms/"+vm.String()+"/console")
	conn, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err != nil {
		t.Fatalf("authorized console handshake failed (status %v): %v", statusOf(resp), err)
	}
	defer conn.Close()

	// A keyless VM always waits for the browser's first "connect" frame --
	// send one offering no key, exactly like the frontend does when the
	// user has no saved credential and hasn't picked a file yet.
	if err := conn.WriteJSON(map[string]any{"type": "connect"}); err != nil {
		t.Fatalf("write connect frame: %v", err)
	}

	var frame map[string]any
	if err := conn.ReadJSON(&frame); err != nil {
		t.Fatalf("read first frame: %v", err)
	}
	if frame["type"] != "error" {
		t.Fatalf("expected an error frame for a VM with no SSH credential configured, got %v", frame)
	}
	msg, _ := frame["message"].(string)
	if !strings.Contains(msg, "No SSH key available") {
		t.Errorf("expected a safe 'no key available' message, got %q", msg)
	}
	for _, forbidden := range []string{"panic", "goroutine", ".go:", "0x"} {
		if strings.Contains(msg, forbidden) {
			t.Errorf("error message leaked an internal detail %q: %s", forbidden, msg)
		}
	}
}

// TestVMConsole_FullSession_InputOutputResizeAndAudit is the end-to-end
// proof against a real (fake) SSH server: a real PTY request, real
// keystrokes relayed to the remote side and real output relayed back, a
// resize, a clean disconnect, and both audit events recorded.
func TestVMConsole_FullSession_InputOutputResizeAndAudit(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)

	hostKeyPEM, _ := generateTestSSHKeyPEM(t)
	hostSigner, err := ssh.ParsePrivateKey([]byte(hostKeyPEM))
	if err != nil {
		t.Fatalf("parse fake server host key: %v", err)
	}
	clientKeyPEM, clientPub := generateTestSSHKeyPEM(t)
	srv := startFakeSSHServer(t, hostSigner, clientPub)

	vm := e.createVMWithAddress(t, project, srv.host, int32(srv.port))
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.attachSSHKeyCredential(t, project, vm, clientKeyPEM)
	if _, err := e.hostKeys.Trust(context.Background(), vm, srv.host, srv.port, 5*time.Second); err != nil {
		t.Fatalf("trust fake server host key: %v", err)
	}

	url := wsURL(e.baseURL, "/api/vms/"+vm.String()+"/console?rows=24&cols=80")
	conn, resp, err := dialerFor(adminClient).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err != nil {
		t.Fatalf("console handshake failed (status %v): %v", statusOf(resp), err)
	}
	defer conn.Close()

	// Send a keystroke; the fake server's shell echoes it back prefixed.
	if err := conn.WriteJSON(map[string]any{"type": "input", "data": base64.StdEncoding.EncodeToString([]byte("hostname\n"))}); err != nil {
		t.Fatalf("write input frame: %v", err)
	}

	// gorilla/websocket permanently poisons a *Conn after any read error
	// (including a deadline timeout) -- ReadJSON must never be called again
	// once it has failed once. So: one deadline covering the whole wait,
	// and any read error is fatal rather than something to retry past.
	//
	// The fake server's echo handler writes its "echo:" prefix and the
	// echoed payload as two separate SSH channel writes, which the real
	// relay legitimately forwards as two separate "output" frames (it
	// relays whatever one Read() call returns, exactly like a real
	// terminal's output arrives in arbitrarily-sized chunks) -- so the
	// assertion accumulates across frames rather than expecting the whole
	// match inside a single one.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var received strings.Builder
	found := false
	for i := 0; i < 20 && !found; i++ {
		var outputFrame map[string]any
		if err := conn.ReadJSON(&outputFrame); err != nil {
			t.Fatalf("read output frame: %v (received so far: %q)", err, received.String())
		}
		if outputFrame["type"] != "output" {
			continue
		}
		data, _ := base64.StdEncoding.DecodeString(outputFrame["data"].(string))
		received.Write(data)
		if strings.Contains(received.String(), "echo:hostname") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the echoed output to contain 'echo:hostname', got %q", received.String())
	}
	_ = conn.SetReadDeadline(time.Time{})

	// By now the shell is confirmed running server-side, so
	// RecordConnectionOutcome (called before the relay loop even starts)
	// has certainly already run -- a successful Console session now marks
	// the VM online exactly like connection-test/discover would, closing
	// the "offline unless actively connected" gap.
	statusResp, statusBody := e.get(t, adminClient, "/api/vms/"+vm.String()+"/connection-status")
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("connection-status after console open = %d, want 200", statusResp.StatusCode)
	}
	if statusBody["connection_status"] != "CONNECTED" {
		t.Errorf("connection_status after console open = %v, want CONNECTED", statusBody["connection_status"])
	}

	// Resize -- must not error, and must not require a new connection.
	if err := conn.WriteJSON(map[string]any{"type": "resize", "rows": 40, "cols": 120}); err != nil {
		t.Fatalf("write resize frame: %v", err)
	}

	assertAuditEventExists(t, e, "VM", vm, services.AuditVMConsoleOpened)

	// Disconnect. The server-side handler's cleanup (including the CLOSED
	// audit event) runs asynchronously right after it notices the
	// connection is gone -- poll briefly rather than assuming it's
	// instantaneous.
	conn.Close()
	if !waitForAuditEvent(t, e, vm, services.AuditVMConsoleClosed, 5*time.Second) {
		t.Error("expected a VM_CONSOLE_CLOSED audit event after disconnect, never observed one")
	}
}

// TestVMConsole_EphemeralKey_KeylessVM_ConnectsWithoutPersisting proves the
// second half of the named-credential rework: a VM with no saved
// credential can still open a real Console session if the browser offers a
// private key on the first WebSocket frame, and that key is used for
// exactly this one connection and never written to ssh_key_credentials.
func TestVMConsole_EphemeralKey_KeylessVM_ConnectsWithoutPersisting(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)

	hostKeyPEM, _ := generateTestSSHKeyPEM(t)
	hostSigner, err := ssh.ParsePrivateKey([]byte(hostKeyPEM))
	if err != nil {
		t.Fatalf("parse fake server host key: %v", err)
	}
	clientKeyPEM, clientPub := generateTestSSHKeyPEM(t)
	srv := startFakeSSHServer(t, hostSigner, clientPub)

	vm := e.createVMWithAddress(t, project, srv.host, int32(srv.port))
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	if _, err := e.hostKeys.Trust(context.Background(), vm, srv.host, srv.port, 5*time.Second); err != nil {
		t.Fatalf("trust fake server host key: %v", err)
	}

	before, err := e.sshKeyCredentials.List(context.Background(), project)
	if err != nil {
		t.Fatalf("list ssh key credentials before: %v", err)
	}

	url := wsURL(e.baseURL, "/api/vms/"+vm.String()+"/console")
	conn, resp, err := dialerFor(adminClient).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err != nil {
		t.Fatalf("console handshake failed (status %v): %v", statusOf(resp), err)
	}
	defer conn.Close()

	if err := conn.WriteJSON(map[string]any{"type": "connect", "private_key": clientKeyPEM}); err != nil {
		t.Fatalf("write connect frame with ephemeral key: %v", err)
	}

	// Prove the session actually opened against the real (fake) SSH server
	// rather than failing safely -- an input echoed back is the same
	// end-to-end proof the credentialed full-session test uses.
	if err := conn.WriteJSON(map[string]any{"type": "input", "data": base64.StdEncoding.EncodeToString([]byte("hi\n"))}); err != nil {
		t.Fatalf("write input frame: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var received strings.Builder
	found := false
	for i := 0; i < 20 && !found; i++ {
		var frame map[string]any
		if err := conn.ReadJSON(&frame); err != nil {
			t.Fatalf("read frame: %v (received so far: %q)", err, received.String())
		}
		if frame["type"] == "error" {
			t.Fatalf("expected the ephemeral key to connect successfully, got error frame: %v", frame)
		}
		if frame["type"] != "output" {
			continue
		}
		data, _ := base64.StdEncoding.DecodeString(frame["data"].(string))
		received.Write(data)
		if strings.Contains(received.String(), "echo:hi") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the echoed output to contain 'echo:hi', got %q", received.String())
	}

	after, err := e.sshKeyCredentials.List(context.Background(), project)
	if err != nil {
		t.Fatalf("list ssh key credentials after: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("ssh_key_credentials count changed from %d to %d -- the ephemeral key must never be persisted", len(before), len(after))
	}

	vmRow, err := e.store.GetVMByResourceID(context.Background(), vm)
	if err != nil {
		t.Fatalf("reload vm: %v", err)
	}
	if vmRow.SshKeyCredentialID.Valid {
		t.Error("vm.ssh_key_credential_id was set by an ephemeral-key console session -- it must stay keyless")
	}
}
