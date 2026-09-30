// Package handlers: vm_console.go implements Step 22's browser-based VM
// console -- an interactive PTY shell tunneled over an authenticated
// WebSocket and an authorized SSH connection, reusing SSHService.Connect
// (internal/services/ssh.go) completely unchanged. The browser never sees
// an SSH credential of any kind; it only ever exchanges JSON frames
// carrying keystrokes/output over the WebSocket, exactly like every other
// WebSocket in this project (internal/handlers/docker_stream.go et al.) --
// this is the first bidirectional one, everything else is push-only.
//
// This is a deliberately different trust model from every other feature
// in this project: once a Console session is open, the connecting user's
// keystrokes execute as arbitrary commands under that VM's own configured
// SSH user, unlike the small, fixed, backend-generated command set every
// other controlled operation (update execution, reboot, database
// remediation) is restricted to. That is why authorization here is
// vm.connect specifically -- docs/authorization.md has reserved this exact
// permission for "a future console endpoint" since Step 3, independent of
// vm.view, and it is enforced here exactly as that document describes:
// RequireAuthentication, then CanAccessVM(user, vmID, "vm.connect")
// (deny-by-default, 404-not-403), only then does any SSH connection begin.
package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

const (
	defaultConsoleRows = 24
	defaultConsoleCols = 80
	consoleReadBufSize = 4096
)

// consoleFirstFrameTimeout bounds how long Console waits for the
// browser's first "connect" frame on the two paths that need one (a
// keyless VM, or ?use_ephemeral_key=1) -- see readConsoleConnectFrame. A
// var, not a const, so a same-package test can lower it.
var consoleFirstFrameTimeout = 10 * time.Second

type VMConsoleHandler struct {
	store          *repository.Store
	authz          *services.AuthorizationService
	ssh            *services.SSHService
	audit          *services.AuditService
	frontendOrigin string
}

func NewVMConsoleHandler(store *repository.Store, authz *services.AuthorizationService, sshSvc *services.SSHService, audit *services.AuditService, frontendOrigin string) *VMConsoleHandler {
	return &VMConsoleHandler{store: store, authz: authz, ssh: sshSvc, audit: audit, frontendOrigin: frontendOrigin}
}

type consoleInboundFrame struct {
	Type       string `json:"type"` // "connect" | "input" | "resize"
	Data       string `json:"data,omitempty"`
	Rows       int    `json:"rows,omitempty"`
	Cols       int    `json:"cols,omitempty"`
	PrivateKey string `json:"private_key,omitempty"` // only meaningful on "connect"
}

type consoleOutboundFrame struct {
	Type    string `json:"type"` // "output" | "error" | "closed"
	Data    string `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

// readConsoleConnectFrame blocks for up to consoleFirstFrameTimeout for
// the browser's first WebSocket message.
func readConsoleConnectFrame(conn *websocket.Conn) (consoleInboundFrame, error) {
	_ = conn.SetReadDeadline(time.Now().Add(consoleFirstFrameTimeout))
	_, msg, err := conn.ReadMessage()
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return consoleInboundFrame{}, err
	}
	var frame consoleInboundFrame
	_ = json.Unmarshal(msg, &frame) // malformed JSON -> zero-value frame, treated as "no key offered"
	return frame, nil
}

// processConsoleInboundFrame handles one "input"/"resize" frame -- shared
// by the one-off replay of a first frame that turned out to carry real
// input/resize (not a pure "connect" handshake) and by the main relay
// loop's per-iteration handling. "connect" (and anything else) is a
// no-op here; it only ever matters in Console's own credential-resolution
// step.
func processConsoleInboundFrame(frame consoleInboundFrame, stdin io.Writer, session *ssh.Session) error {
	switch frame.Type {
	case "input":
		data, err := base64.StdEncoding.DecodeString(frame.Data)
		if err != nil {
			return nil
		}
		_, err = stdin.Write(data)
		return err
	case "resize":
		// Never opens a new SSH session -- WindowChange resizes the
		// existing remote PTY in place (spec §35).
		if frame.Rows > 0 && frame.Cols > 0 && frame.Rows <= 1000 && frame.Cols <= 1000 {
			_ = session.WindowChange(frame.Rows, frame.Cols)
		}
	}
	return nil
}

func parseTerminalSize(r *http.Request) (rows, cols int) {
	rows, cols = defaultConsoleRows, defaultConsoleCols
	if v, err := strconv.Atoi(r.URL.Query().Get("rows")); err == nil && v > 0 && v <= 1000 {
		rows = v
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("cols")); err == nil && v > 0 && v <= 1000 {
		cols = v
	}
	return rows, cols
}

// Console handles GET /api/vms/:id/console: authenticate, authorize
// (vm.connect, 404-not-403), upgrade to a WebSocket, open one SSH session
// with a PTY, and relay bytes in both directions until either side
// disconnects. Every exit path closes the SSH session and the underlying
// SSH client exactly once (via the shared finish() below), so a client
// that simply closes the browser tab can never leak a goroutine, PTY, or
// SSH connection.
func (h *VMConsoleHandler) Console(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	allowed, err := h.authz.CanAccessVM(r.Context(), user, resourceID, services.PermVMConnect)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return
	}
	if !allowed {
		// 404, not 403 -- matches every other VM-scoped endpoint's IDOR
		// discipline (docs/authorization.md §3): a Member probing an
		// unauthorized VM ID must not learn it exists, whether or not they
		// hold vm.view on it.
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}

	rows, cols := parseTerminalSize(r)

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "" || httpx.OriginAllowed(h.frontendOrigin, origin)
		},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade already wrote its own HTTP error response
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	vm, err := h.store.GetVMByResourceID(ctx, resourceID)
	if err != nil {
		_ = conn.WriteJSON(consoleOutboundFrame{Type: "error", Message: "Unable to connect to VM: check the VM availability and SSH configuration."})
		return
	}

	// Deployment-safety decision: only wait for a first frame when it's
	// actually needed. A VM with a stored credential and no
	// ?use_ephemeral_key=1 connects exactly as before -- zero wait, zero
	// frontend coordination required for the common case. Waiting only
	// engages for a keyless VM (which previously couldn't open Console at
	// all -- no regression) or when the frontend explicitly opts in to
	// offer "use a different key for just this session."
	waitForFirstFrame := !vm.SshKeyCredentialID.Valid || r.URL.Query().Get("use_ephemeral_key") == "1"

	var client *ssh.Client
	var pendingFrame *consoleInboundFrame

	if !waitForFirstFrame {
		client, err = h.ssh.Connect(ctx, resourceID)
	} else {
		frame, ferr := readConsoleConnectFrame(conn)
		if ferr != nil {
			_ = conn.WriteJSON(consoleOutboundFrame{Type: "error", Message: "Timed out waiting for an SSH key. Select a saved key or provide one to connect."})
			return
		}
		pendingFrame = &frame
		switch {
		case frame.PrivateKey != "":
			var signer ssh.Signer
			signer, err = services.ParseSSHPrivateKey([]byte(frame.PrivateKey))
			if err != nil {
				if errors.Is(err, services.ErrPassphraseProtectedKey) {
					_ = conn.WriteJSON(consoleOutboundFrame{Type: "error", Message: err.Error()})
				} else {
					_ = conn.WriteJSON(consoleOutboundFrame{Type: "error", Message: "invalid SSH private key"})
				}
				return
			}
			client, err = h.ssh.ConnectWithSigner(ctx, resourceID, signer)
		case vm.SshKeyCredentialID.Valid:
			client, err = h.ssh.Connect(ctx, resourceID)
		default:
			_ = conn.WriteJSON(consoleOutboundFrame{Type: "error", Message: "No SSH key available -- select a saved key or provide one to connect."})
			return
		}
	}
	if err != nil {
		_ = conn.WriteJSON(consoleOutboundFrame{Type: "error", Message: "Unable to connect to VM: " + safeSSHErrorMessage(err)})
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		_ = conn.WriteJSON(consoleOutboundFrame{Type: "error", Message: "Unable to open a shell session on this VM."})
		return
	}
	defer session.Close()

	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := session.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		_ = conn.WriteJSON(consoleOutboundFrame{Type: "error", Message: "This VM's SSH server refused an interactive terminal request."})
		return
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		_ = conn.WriteJSON(consoleOutboundFrame{Type: "error", Message: "Unable to open a shell session on this VM."})
		return
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = conn.WriteJSON(consoleOutboundFrame{Type: "error", Message: "Unable to open a shell session on this VM."})
		return
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		_ = conn.WriteJSON(consoleOutboundFrame{Type: "error", Message: "Unable to open a shell session on this VM."})
		return
	}

	if err := session.Shell(); err != nil {
		_ = conn.WriteJSON(consoleOutboundFrame{Type: "error", Message: "Unable to start an interactive shell on this VM."})
		return
	}

	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &user.ID, Action: services.AuditVMConsoleOpened, ResourceType: "VM", ResourceID: &resourceID,
	})
	// A live shell just proved this VM reachable -- mark it online exactly
	// like a successful connection-test/discovery attempt would (reuses
	// RecordConnectionOutcome unmodified). Deliberately not mirrored on
	// close: closing a terminal tab doesn't mean the VM went offline, and
	// forcing that transition would contradict the existing "offline only
	// follows an actual failed attempt" model used everywhere else.
	_ = services.RecordConnectionOutcome(r.Context(), h.store, resourceID, vm.ID, nil)

	var closeOnce sync.Once
	done := make(chan struct{})
	finish := func() {
		closeOnce.Do(func() {
			cancel()
			_ = conn.Close()
			_ = session.Close()
			_ = client.Close()
			close(done)
		})
	}
	defer finish()
	defer func() {
		// Best-effort, on its own context: by the time this runs, ctx (tied
		// to the request/connection lifetime) is already cancelled above.
		_ = h.audit.Log(context.Background(), services.AuditEvent{
			UserID: &user.ID, Action: services.AuditVMConsoleClosed, ResourceType: "VM", ResourceID: &resourceID,
		})
	}()

	// SSH -> WebSocket (stdout and stderr). Both run concurrently on their
	// own goroutines, but gorilla/websocket allows only one concurrent
	// writer per *Conn -- writeMu serializes their conn.WriteJSON calls so
	// a chatty stderr can never corrupt/interleave a stdout frame (or vice
	// versa). Never logged, never persisted -- see the package doc comment
	// and spec §37: only the open/close audit events above exist for a
	// console session, terminal content is not one of them.
	var writeMu sync.Mutex
	go relayConsoleOutput(conn, &writeMu, stdout, finish)
	// stderr merges into the same "output" frame type -- a real PTY
	// already interleaves both from the remote shell's perspective, this
	// is just a safety net for anything a program writes directly to fd 2.
	go relayConsoleOutput(conn, &writeMu, stderr, func() {})

	// A "connect" frame read during credential resolution never carries
	// real input/resize, but a client that raced ahead and combined its
	// key with an immediate keystroke would have that keystroke lost
	// without this replay.
	if pendingFrame != nil {
		if err := processConsoleInboundFrame(*pendingFrame, stdin, session); err != nil {
			return
		}
	}

	// WebSocket -> SSH (stdin) + resize control frames. Runs on this
	// goroutine; returns (and triggers finish() via the defer above) once
	// the browser disconnects or sends something unreadable enough times
	// that continuing is pointless.
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var frame consoleInboundFrame
		if err := json.Unmarshal(msg, &frame); err != nil {
			continue
		}
		if err := processConsoleInboundFrame(frame, stdin, session); err != nil {
			return
		}
	}
}

// relayConsoleOutput copies from src (the SSH session's stdout or stderr
// pipe) to the WebSocket as "output" frames until src returns an error
// (session ended) or the WebSocket write fails (client gone), then calls
// onDone exactly once to let the caller unwind everything else. writeMu is
// shared with the sibling stdout/stderr relay so the two never call
// conn.WriteJSON concurrently.
func relayConsoleOutput(conn *websocket.Conn, writeMu *sync.Mutex, src io.Reader, onDone func()) {
	defer onDone()
	buf := make([]byte, consoleReadBufSize)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			frame := consoleOutboundFrame{Type: "output", Data: base64.StdEncoding.EncodeToString(buf[:n])}
			writeMu.Lock()
			writeErr := conn.WriteJSON(frame)
			writeMu.Unlock()
			if writeErr != nil {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}

// safeSSHErrorMessage extracts SSHError's already-sanitized Message
// (internal/services/ssh_errors.go: "none of them ever carry a private
// key, ciphertext, or raw SSH library internals"), falling back to a
// generic message for the rare case Connect returns something else.
func safeSSHErrorMessage(err error) string {
	var sshErr *services.SSHError
	if errors.As(err, &sshErr) {
		return sshErr.Message
	}
	return "check the VM availability and SSH configuration."
}
