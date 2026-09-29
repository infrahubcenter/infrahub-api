// Package handlers: docker_logs.go implements Step 24's Docker Logs
// live-tail (GET /api/docker/containers/:containerId/logs/stream) --
// authenticate, resolve the container to its owning VM, authorize via
// docker.logs (a Project/Group-scoped grant, independent of vm.view),
// then stream `docker logs -f` over the existing SSH connection straight
// to the browser. Live-tail only, by design: nothing is stored server-side
// from the stream itself. Step 25 (per a later request) added Search
// below, backed by the separate background capture in
// services/docker_log_capture.go -- history there goes back up to the
// configured retention window regardless of whether anyone tailed live.
package handlers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

type DockerLogsHandler struct {
	store          *repository.Store
	authz          *services.AuthorizationService
	ssh            *services.SSHService
	audit          *services.AuditService
	frontendOrigin string
	logRetention   time.Duration
}

func NewDockerLogsHandler(store *repository.Store, authz *services.AuthorizationService, sshSvc *services.SSHService, audit *services.AuditService, frontendOrigin string, logRetention time.Duration) *DockerLogsHandler {
	return &DockerLogsHandler{store: store, authz: authz, ssh: sshSvc, audit: audit, frontendOrigin: frontendOrigin, logRetention: logRetention}
}

// canAccessDockerLogs mirrors AuthorizationService.CanAccessDockerFeature's
// own true/false/error shape -- kept as a thin wrapper so Stream/Search
// read identically to k8s_logs.go's canAccessK8sLogs.
func (h *DockerLogsHandler) canAccessDockerLogs(ctx context.Context, user services.AuthenticatedUser, vmResourceID, containerID uuid.UUID) (bool, error) {
	return h.authz.CanAccessDockerFeature(ctx, user, vmResourceID, services.PermDockerLogs)
}

// isSafeDockerContainerID mirrors DockerClient's own hex-ID validation
// (internal/services/docker_client.go's isDockerHexID) -- a defensive
// re-check immediately before this container_id is interpolated into a
// remote shell command, even though it's already sourced from a
// docker_containers row the discovery scan itself validated the same way
// at insert time (never raw request input).
func isSafeDockerContainerID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

type dockerLogsOutboundFrame struct {
	Type    string `json:"type"` // "log" | "error" | "closed"
	Line    string `json:"line,omitempty"`
	Message string `json:"message,omitempty"`
	// Severity/Category/Suggestion classify a "log" frame's Line (see
	// services.ClassifyLogLine) -- always present on "log" frames, always
	// empty on "error"/"closed" ones.
	Severity   string `json:"severity,omitempty"`
	Category   string `json:"category,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
}

// Stream handles GET /api/docker/containers/:containerId/logs/stream.
func (h *DockerLogsHandler) Stream(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	containerID, err := uuid.Parse(r.PathValue("containerId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "container not found")
		return
	}
	container, err := h.store.GetDockerContainerWithVMByID(r.Context(), containerID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "container not found")
		return
	}
	if container.VmStatus == "DISABLED" {
		httpx.WriteError(w, http.StatusNotFound, "container not found")
		return
	}

	allowed, err := h.canAccessDockerLogs(r.Context(), user, container.VmResourceID, containerID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return
	}
	if !allowed {
		httpx.WriteError(w, http.StatusNotFound, "container not found")
		return
	}
	if !isSafeDockerContainerID(container.ContainerID) {
		httpx.WriteError(w, http.StatusInternalServerError, "container record is invalid")
		return
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "" || origin == h.frontendOrigin
		},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := h.ssh.Connect(ctx, container.VmResourceID)
	if err != nil {
		_ = conn.WriteJSON(dockerLogsOutboundFrame{Type: "error", Message: "Unable to connect to VM: " + safeSSHErrorMessage(err)})
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		_ = conn.WriteJSON(dockerLogsOutboundFrame{Type: "error", Message: "Unable to open a session on this VM."})
		return
	}
	defer session.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = conn.WriteJSON(dockerLogsOutboundFrame{Type: "error", Message: "Unable to open a session on this VM."})
		return
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		_ = conn.WriteJSON(dockerLogsOutboundFrame{Type: "error", Message: "Unable to open a session on this VM."})
		return
	}

	command := fmt.Sprintf("docker logs -f --tail 200 --timestamps %s", container.ContainerID)
	if err := session.Start(command); err != nil {
		_ = conn.WriteJSON(dockerLogsOutboundFrame{Type: "error", Message: "Unable to start log streaming for this container."})
		return
	}

	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &user.ID, Action: services.AuditDockerLogsOpened, ResourceType: "VM", ResourceID: &container.VmResourceID,
		Metadata: map[string]any{"container_id": containerID, "container_name": container.Name},
	})

	var closeOnce sync.Once
	finish := func() {
		closeOnce.Do(func() {
			cancel()
			_ = conn.Close()
			_ = session.Close()
			_ = client.Close()
		})
	}
	defer finish()
	defer func() {
		_ = h.audit.Log(context.Background(), services.AuditEvent{
			UserID: &user.ID, Action: services.AuditDockerLogsClosed, ResourceType: "VM", ResourceID: &container.VmResourceID,
			Metadata: map[string]any{"container_id": containerID, "container_name": container.Name},
		})
	}()

	// Both stdout and stderr relay concurrently, but gorilla/websocket
	// allows only one concurrent writer per *Conn -- writeMu serializes
	// their conn.WriteJSON calls (same fix VM Console needed for the
	// identical stdout/stderr race).
	var writeMu sync.Mutex
	go relayDockerLogLines(conn, &writeMu, stdout, finish)
	go relayDockerLogLines(conn, &writeMu, stderr, func() {})

	// This stream is push-only (identical convention to the Docker stats
	// stream and every other non-Console WebSocket in this app) -- the
	// only purpose of reading here is to detect the browser disconnecting
	// or sending a close frame.
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

// relayDockerLogLines copies from src (the SSH session's stdout or
// stderr) to the WebSocket as "log" frames, splitting on newlines so each
// frame is one line rather than an arbitrary byte chunk -- log content is
// plain text, never base64, since (unlike VM Console) there is no
// interactive terminal/control-sequence stream to preserve byte-for-byte.
func relayDockerLogLines(conn *websocket.Conn, writeMu *sync.Mutex, src io.Reader, onDone func()) {
	defer onDone()
	writeLine := func(line string) error {
		c := services.ClassifyLogLine(line)
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteJSON(dockerLogsOutboundFrame{
			Type: "log", Line: line, Severity: string(c.Severity), Category: c.Category, Suggestion: c.Suggestion,
		})
	}
	buf := make([]byte, 4096)
	var partial []byte
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			partial = append(partial, buf[:n]...)
			for {
				idx := bytes.IndexByte(partial, '\n')
				if idx < 0 {
					break
				}
				line := string(partial[:idx])
				partial = partial[idx+1:]
				if writeLine(line) != nil {
					return
				}
			}
		}
		if readErr != nil {
			if len(partial) > 0 {
				_ = writeLine(string(partial))
			}
			return
		}
	}
}

// Search handles GET /api/docker/containers/:containerId/logs/search --
// searches the background-captured history (services/docker_log_capture.go),
// bounded to (at most) the retention window. Same auth as Stream --
// docker.logs, independent of docker.monitor and of vm.view/vm.connect --
// and the same 404-not-403 IDOR discipline: an unauthorized container looks
// identical to a nonexistent one.
//
// Query params: q (optional substring filter), from/to (RFC3339, clamped
// to the retention window), limit (default 200, max 1000), offset.
func (h *DockerLogsHandler) Search(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	containerID, err := uuid.Parse(r.PathValue("containerId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "container not found")
		return
	}
	container, err := h.store.GetDockerContainerWithVMByID(r.Context(), containerID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "container not found")
		return
	}
	if container.VmStatus == "DISABLED" {
		httpx.WriteError(w, http.StatusNotFound, "container not found")
		return
	}
	allowed, err := h.canAccessDockerLogs(r.Context(), user, container.VmResourceID, containerID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return
	}
	if !allowed {
		httpx.WriteError(w, http.StatusNotFound, "container not found")
		return
	}

	q := r.URL.Query()
	now := time.Now()
	retentionCutoff := now.Add(-h.logRetention)

	from := retentionCutoff
	if v := q.Get("from"); v != "" {
		if parsed, err := time.Parse(time.RFC3339, v); err == nil && parsed.After(from) {
			from = parsed
		}
	}
	to := now
	if v := q.Get("to"); v != "" {
		if parsed, err := time.Parse(time.RFC3339, v); err == nil && parsed.Before(to) {
			to = parsed
		}
	}
	if to.Before(from) {
		to = from
	}

	var searchTerm pgtype.Text
	if term := strings.TrimSpace(q.Get("q")); term != "" {
		searchTerm = pgutil.Text(term)
	}

	limit := int32(200)
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = int32(n)
		}
	}
	offset := int32(0)
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = int32(n)
		}
	}

	severityFilter, hasSeverityFilter := parseLogSeverityFilter(q.Get("severity"))

	fromTs, toTs := pgutil.Timestamptz(from), pgutil.Timestamptz(to)

	// The Healthy/Warning/Error/Critical counts (and the severity-filtered
	// page itself, when requested) are computed over this bounded scan --
	// see logSeverityScanCap's doc comment.
	scanRows, err := h.store.SearchDockerLogLines(r.Context(), generated.SearchDockerLogLinesParams{
		DockerContainerID: containerID, FromTs: fromTs, ToTs: toTs, Query: searchTerm, PageLimit: logSeverityScanCap, PageOffset: 0,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to search logs")
		return
	}
	var counts services.LogSeverityCounts
	classifiedScan := make([]logSearchLineDTO, 0, len(scanRows))
	for _, row := range scanRows {
		dto := toLogSearchLineDTO(row.ID.String(), row.LoggedAt.Time, row.Line)
		counts.Add(services.LogSeverity(dto.Severity))
		classifiedScan = append(classifiedScan, dto)
	}

	var items []logSearchLineDTO
	var total int64
	if hasSeverityFilter {
		var filtered []logSearchLineDTO
		for _, dto := range classifiedScan {
			if dto.Severity == string(severityFilter) {
				filtered = append(filtered, dto)
			}
		}
		total = int64(len(filtered))
		items = paginateClassifiedLines(filtered, limit, offset)
	} else {
		rows, err := h.store.SearchDockerLogLines(r.Context(), generated.SearchDockerLogLinesParams{
			DockerContainerID: containerID, FromTs: fromTs, ToTs: toTs, Query: searchTerm, PageLimit: limit, PageOffset: offset,
		})
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to search logs")
			return
		}
		dbTotal, err := h.store.CountDockerLogLines(r.Context(), generated.CountDockerLogLinesParams{
			DockerContainerID: containerID, FromTs: fromTs, ToTs: toTs, Query: searchTerm,
		})
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to search logs")
			return
		}
		total = dbTotal
		items = make([]logSearchLineDTO, 0, len(rows))
		for _, row := range rows {
			items = append(items, toLogSearchLineDTO(row.ID.String(), row.LoggedAt.Time, row.Line))
		}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"lines": items, "total": total, "retention_cutoff": retentionCutoff.Format(time.RFC3339), "counts": counts,
	})
}
