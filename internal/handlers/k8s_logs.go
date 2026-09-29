// Package handlers: k8s_logs.go implements Step 25's Kubernetes pod-logs
// live-tail (GET /api/k8s/pods/:podId/logs/stream) -- authenticate,
// resolve the pod to its owning cluster, authorize via k8s.logs (a
// Project/Group-scoped grant, independent of k8s.monitor), then relay the
// pod's logs from its cluster's connected agent to the browser. Mirrors
// docker_logs.go's Stream exactly in spirit, except the source is
// K8sService.StreamLogs' already-line-delimited channel (the agent itself
// splits lines) rather than a raw byte reader, so no buffering/splitting
// is needed here. Live-tail only: nothing is stored server-side, and only
// open/close events are audited, never log content.
package handlers

import (
	"context"
	"errors"
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

type K8sLogsHandler struct {
	store          *repository.Store
	authz          *services.AuthorizationService
	k8s            *services.K8sService
	audit          *services.AuditService
	frontendOrigin string
	logRetention   time.Duration
}

func NewK8sLogsHandler(store *repository.Store, authz *services.AuthorizationService, k8sSvc *services.K8sService, audit *services.AuditService, frontendOrigin string, logRetention time.Duration) *K8sLogsHandler {
	return &K8sLogsHandler{store: store, authz: authz, k8s: k8sSvc, audit: audit, frontendOrigin: frontendOrigin, logRetention: logRetention}
}

// canAccessK8sLogs mirrors DockerLogsHandler.canAccessDockerLogs exactly.
func (h *K8sLogsHandler) canAccessK8sLogs(ctx context.Context, user services.AuthenticatedUser, clusterResourceID, podID uuid.UUID) (bool, error) {
	return h.authz.CanAccessK8sFeature(ctx, user, clusterResourceID, services.PermK8sLogs)
}

type k8sLogsOutboundFrame struct {
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

// Stream handles GET /api/k8s/pods/:podId/logs/stream.
func (h *K8sLogsHandler) Stream(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	podID, err := uuid.Parse(r.PathValue("podId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "pod not found")
		return
	}
	pod, err := h.store.GetK8sPodWithClusterByID(r.Context(), podID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "pod not found")
		return
	}
	if pod.ClusterDeletedAt.Valid {
		httpx.WriteError(w, http.StatusNotFound, "pod not found")
		return
	}

	allowed, err := h.canAccessK8sLogs(r.Context(), user, pod.ClusterResourceID, podID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return
	}
	if !allowed {
		httpx.WriteError(w, http.StatusNotFound, "pod not found")
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

	stream, stopStream, err := h.k8s.StreamLogs(pod.K8sClusterID, pod.Namespace, pod.PodName)
	if err != nil {
		message := "check that the cluster's agent is installed and connected."
		if errors.Is(err, services.ErrK8sAgentOffline) {
			message = "No agent is currently connected for this cluster."
		}
		_ = conn.WriteJSON(k8sLogsOutboundFrame{Type: "error", Message: message})
		return
	}

	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &user.ID, Action: services.AuditK8sLogsOpened, ResourceType: "K8S_CLUSTER", ResourceID: &pod.ClusterResourceID,
		Metadata: map[string]any{"pod_id": podID, "pod_name": pod.PodName, "namespace": pod.Namespace},
	})

	var closeOnce sync.Once
	finish := func() {
		closeOnce.Do(func() {
			stopStream()
			_ = conn.Close()
		})
	}
	defer finish()
	defer func() {
		_ = h.audit.Log(context.Background(), services.AuditEvent{
			UserID: &user.ID, Action: services.AuditK8sLogsClosed, ResourceType: "K8S_CLUSTER", ResourceID: &pod.ClusterResourceID,
			Metadata: map[string]any{"pod_id": podID, "pod_name": pod.PodName, "namespace": pod.Namespace},
		})
	}()

	go relayK8sAgentLogStream(conn, stream, finish)

	// Push-only stream (same convention as Docker Logs/Docker stats) -- the
	// only purpose of reading here is to detect the browser disconnecting.
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

// relayK8sAgentLogStream forwards the agent's already-line-delimited
// messages to the WebSocket as "log" frames until the stream ends (agent
// sent "done", the agent connection dropped mid-stream, or a write to the
// browser fails) -- only one goroutine ever writes here, so no writer
// mutex is needed.
func relayK8sAgentLogStream(conn *websocket.Conn, stream <-chan services.K8sAgentMessage, onDone func()) {
	defer onDone()
	for msg := range stream {
		switch msg.Type {
		case services.K8sAgentMsgLogLine:
			c := services.ClassifyLogLine(msg.Line)
			if conn.WriteJSON(k8sLogsOutboundFrame{
				Type: "log", Line: msg.Line, Severity: string(c.Severity), Category: c.Category, Suggestion: c.Suggestion,
			}) != nil {
				return
			}
		case services.K8sAgentMsgDone:
			return
		case services.K8sAgentMsgError:
			_ = conn.WriteJSON(k8sLogsOutboundFrame{Type: "error", Message: msg.Message})
			return
		}
	}
}

// Search handles GET /api/k8s/pods/:podId/logs/search -- searches the
// background-captured history (services/k8s_log_capture.go), bounded to
// (at most) the retention window. Mirrors DockerLogsHandler.Search
// exactly: same query params, same clamping, same 404-not-403 discipline.
func (h *K8sLogsHandler) Search(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	podID, err := uuid.Parse(r.PathValue("podId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "pod not found")
		return
	}
	pod, err := h.store.GetK8sPodWithClusterByID(r.Context(), podID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "pod not found")
		return
	}
	if pod.ClusterDeletedAt.Valid {
		httpx.WriteError(w, http.StatusNotFound, "pod not found")
		return
	}
	allowed, err := h.canAccessK8sLogs(r.Context(), user, pod.ClusterResourceID, podID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return
	}
	if !allowed {
		httpx.WriteError(w, http.StatusNotFound, "pod not found")
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
	scanRows, err := h.store.SearchK8sPodLogLines(r.Context(), generated.SearchK8sPodLogLinesParams{
		K8sPodID: podID, FromTs: fromTs, ToTs: toTs, Query: searchTerm, PageLimit: logSeverityScanCap, PageOffset: 0,
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
		rows, err := h.store.SearchK8sPodLogLines(r.Context(), generated.SearchK8sPodLogLinesParams{
			K8sPodID: podID, FromTs: fromTs, ToTs: toTs, Query: searchTerm, PageLimit: limit, PageOffset: offset,
		})
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to search logs")
			return
		}
		dbTotal, err := h.store.CountK8sPodLogLines(r.Context(), generated.CountK8sPodLogLinesParams{
			K8sPodID: podID, FromTs: fromTs, ToTs: toTs, Query: searchTerm,
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
