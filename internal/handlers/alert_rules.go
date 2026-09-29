package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// AlertRulesHandler implements Step 16's Admin-only alert rule
// management API (spec §8/§33: "Only Admin can modify alert rules").
type AlertRulesHandler struct {
	store *repository.Store
	rules *services.AlertRuleService
	audit *services.AuditService
}

// NewAlertRulesHandler creates an AlertRulesHandler.
func NewAlertRulesHandler(store *repository.Store, rules *services.AlertRuleService, audit *services.AuditService) *AlertRulesHandler {
	return &AlertRulesHandler{store: store, rules: rules, audit: audit}
}

type alertRuleDTO struct {
	ID                            string   `json:"id"`
	ResourceID                    string   `json:"resource_id"`
	ContainerID                   *string  `json:"container_id,omitempty"`
	K8sPodID                      *string  `json:"k8s_pod_id,omitempty"`
	DockerHostContainerSightingID *string  `json:"docker_host_container_sighting_id,omitempty"`
	AlertType                     string   `json:"alert_type"`
	Metric                        string   `json:"metric"`
	Condition                     string   `json:"condition"`
	Threshold                     float64  `json:"threshold"`
	RecoveryThreshold             *float64 `json:"recovery_threshold,omitempty"`
	DurationSeconds               int32    `json:"duration_seconds"`
	Severity                      string   `json:"severity"`
	NotificationPolicyID          *string  `json:"notification_policy_id,omitempty"`
	Enabled                       bool     `json:"enabled"`
	SuppressedUntil               *string  `json:"suppressed_until,omitempty"`
	SuppressedReason              string   `json:"suppressed_reason,omitempty"`
	CreatedAt                     string   `json:"created_at"`
}

func toAlertRuleDTO(rule generated.AlertRule) alertRuleDTO {
	dto := alertRuleDTO{
		ID: rule.ID.String(), ResourceID: rule.ResourceID.String(), AlertType: rule.AlertType, Metric: rule.Metric,
		Condition: rule.Condition, Threshold: rule.Threshold, RecoveryThreshold: pgutil.Float8Ptr(rule.RecoveryThreshold),
		DurationSeconds: rule.DurationSeconds, Severity: rule.Severity, Enabled: rule.Enabled,
		SuppressedReason: pgutil.TextOrEmpty(rule.SuppressedReason), CreatedAt: formatTimestamptzOrEmpty(rule.CreatedAt),
		SuppressedUntil: formatTimestamptz(rule.SuppressedUntil),
	}
	if rule.ContainerID.Valid {
		id := pgutil.UUID(rule.ContainerID).String()
		dto.ContainerID = &id
	}
	if rule.K8sPodID.Valid {
		id := pgutil.UUID(rule.K8sPodID).String()
		dto.K8sPodID = &id
	}
	if rule.DockerHostContainerSightingID.Valid {
		id := pgutil.UUID(rule.DockerHostContainerSightingID).String()
		dto.DockerHostContainerSightingID = &id
	}
	if rule.NotificationPolicyID.Valid {
		id := pgutil.UUID(rule.NotificationPolicyID).String()
		dto.NotificationPolicyID = &id
	}
	return dto
}

// Templates handles GET /api/alert-rules/templates -- the predefined
// catalog (spec §40) the "New Rule" UI builds its picker from.
func (h *AlertRulesHandler) Templates(w http.ResponseWriter, r *http.Request) {
	items := make([]map[string]any, 0, len(services.AlertTemplates))
	for _, t := range services.AlertTemplates {
		items = append(items, map[string]any{
			"type": t.Type, "metric": t.Metric, "label": t.Label, "default_condition": t.DefaultCondition,
			"default_threshold": t.DefaultThreshold, "default_duration_seconds": t.DefaultDuration,
			"default_severity": t.DefaultSeverity, "applies_to_resource": t.AppliesToResource,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"templates": items})
}

type alertRuleRequest struct {
	ResourceID  string `json:"resource_id"`
	ContainerID string `json:"container_id,omitempty"`
	K8sPodID    string `json:"k8s_pod_id,omitempty"`
	// DockerHostContainerID is the raw Docker container id string (as
	// returned by GET /api/docker/hosts/:id/containers -- live, never
	// persisted with a name/status of its own, see migration 055's own
	// doc comment) -- unlike k8s_pod_id/container_id, which already name
	// a real persisted row a discovery scheduler wrote, this one is
	// resolved into a docker_host_container_sightings row (upserted,
	// idempotent) by Create below before it ever reaches AlertRuleService.
	DockerHostContainerID string   `json:"docker_host_container_id,omitempty"`
	AlertType             string   `json:"alert_type"`
	Condition             string   `json:"condition"`
	Threshold             float64  `json:"threshold"`
	RecoveryThreshold     *float64 `json:"recovery_threshold,omitempty"`
	DurationSeconds       int32    `json:"duration_seconds"`
	Severity              string   `json:"severity"`
	NotificationPolicyID  string   `json:"notification_policy_id,omitempty"`
	Enabled               bool     `json:"enabled"`
}

// Create handles POST /api/alert-rules (Admin-only).
func (h *AlertRulesHandler) Create(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireAdminActor(w, r)
	if !ok {
		return
	}
	var req alertRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	resourceID, err := uuid.Parse(req.ResourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid resource_id")
		return
	}
	var containerID *uuid.UUID
	if req.ContainerID != "" {
		id, err := uuid.Parse(req.ContainerID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid container_id")
			return
		}
		containerID = &id
	}
	var k8sPodID *uuid.UUID
	if req.K8sPodID != "" {
		id, err := uuid.Parse(req.K8sPodID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid k8s_pod_id")
			return
		}
		k8sPodID = &id
	}
	var dockerHostContainerSightingID *uuid.UUID
	if req.DockerHostContainerID != "" {
		if !isSafeDockerContainerID(req.DockerHostContainerID) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid docker_host_container_id")
			return
		}
		sighting, err := h.store.UpsertDockerHostContainerSighting(r.Context(), generated.UpsertDockerHostContainerSightingParams{
			DockerHostResourceID: resourceID, ContainerID: req.DockerHostContainerID,
		})
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to resolve docker host container")
			return
		}
		dockerHostContainerSightingID = &sighting.ID
	}
	var policyID *uuid.UUID
	if req.NotificationPolicyID != "" {
		id, err := uuid.Parse(req.NotificationPolicyID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid notification_policy_id")
			return
		}
		policyID = &id
	}

	rule, err := h.rules.Create(r.Context(), services.CreateRuleInput{
		ResourceID: resourceID, ContainerID: containerID, K8sPodID: k8sPodID, DockerHostContainerSightingID: dockerHostContainerSightingID,
		AlertType: services.AlertType(req.AlertType),
		Condition: services.AlertCondition(req.Condition), Threshold: req.Threshold, RecoveryThreshold: req.RecoveryThreshold,
		DurationSeconds: req.DurationSeconds, Severity: services.AlertSeverity(req.Severity), NotificationPolicyID: policyID, Enabled: req.Enabled,
	}, actor.ID)
	if err != nil {
		writeAlertRuleError(w, err)
		return
	}
	_ = h.audit.Log(r.Context(), services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditAlertRuleCreated, ResourceType: "ALERT_RULE", ResourceID: &rule.ID,
		Metadata: map[string]any{"resource_id": resourceID, "alert_type": rule.AlertType},
	})
	httpx.WriteJSON(w, http.StatusCreated, toAlertRuleDTO(rule))
}

// Update handles PUT /api/alert-rules/:id (Admin-only).
func (h *AlertRulesHandler) Update(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireAdminActor(w, r)
	if !ok {
		return
	}
	ruleID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "alert rule not found")
		return
	}
	var req alertRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var policyID *uuid.UUID
	if req.NotificationPolicyID != "" {
		id, err := uuid.Parse(req.NotificationPolicyID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid notification_policy_id")
			return
		}
		policyID = &id
	}
	rule, err := h.rules.Update(r.Context(), ruleID, services.UpdateRuleInput{
		Condition: services.AlertCondition(req.Condition), Threshold: req.Threshold, RecoveryThreshold: req.RecoveryThreshold,
		DurationSeconds: req.DurationSeconds, Severity: services.AlertSeverity(req.Severity), NotificationPolicyID: policyID, Enabled: req.Enabled,
	})
	if err != nil {
		writeAlertRuleError(w, err)
		return
	}
	_ = h.audit.Log(r.Context(), services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditAlertRuleUpdated, ResourceType: "ALERT_RULE", ResourceID: &rule.ID,
	})
	httpx.WriteJSON(w, http.StatusOK, toAlertRuleDTO(rule))
}

// Get handles GET /api/alert-rules/:id (Admin-only).
func (h *AlertRulesHandler) Get(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAdminActor(w, r); !ok {
		return
	}
	ruleID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "alert rule not found")
		return
	}
	rule, err := h.rules.Get(r.Context(), ruleID)
	if err != nil {
		writeAlertRuleError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toAlertRuleDTO(rule))
}

// ListForResource handles GET /api/resources/:resourceId/alert-rules (Admin-only).
func (h *AlertRulesHandler) ListForResource(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAdminActor(w, r); !ok {
		return
	}
	resourceID, err := uuid.Parse(r.PathValue("resourceId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "resource not found")
		return
	}
	rules, err := h.store.ListAlertRulesByResource(r.Context(), resourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load alert rules")
		return
	}
	items := make([]alertRuleDTO, 0, len(rules))
	for _, rule := range rules {
		items = append(items, toAlertRuleDTO(rule))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"alert_rules": items})
}

// ListGlobal handles GET /api/alert-rules (Admin-only).
func (h *AlertRulesHandler) ListGlobal(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAdminActor(w, r); !ok {
		return
	}
	rows, err := h.store.ListAlertRulesGlobal(r.Context(), nil)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load alert rules")
		return
	}
	items := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		dto := toAlertRuleDTO(generated.AlertRule{
			ID: row.ID, ResourceID: row.ResourceID, ContainerID: row.ContainerID, K8sPodID: row.K8sPodID,
			DockerHostContainerSightingID: row.DockerHostContainerSightingID, AlertType: row.AlertType, Metric: row.Metric,
			Condition: row.Condition, Threshold: row.Threshold, RecoveryThreshold: row.RecoveryThreshold, DurationSeconds: row.DurationSeconds,
			Severity: row.Severity, NotificationPolicyID: row.NotificationPolicyID, Enabled: row.Enabled, SuppressedUntil: row.SuppressedUntil,
			SuppressedReason: row.SuppressedReason, CreatedAt: row.CreatedAt,
		})
		item := map[string]any{
			"rule": dto, "resource_name": row.ResourceName, "resource_type": row.ResourceType, "workspace_id": row.WorkspaceID.String(),
		}
		// Display-only extras (migration 058) so the list page can show
		// exactly which pod/container a K8s/Docker-Host-scoped rule
		// targets, the same way it already shows a VM-scoped rule's
		// container_id.
		if row.K8sPodName.Valid {
			item["k8s_pod_name"] = row.K8sPodName.String
			item["k8s_pod_namespace"] = row.K8sPodNamespace.String
		}
		if row.DockerHostContainerDockerID.Valid {
			item["docker_host_container_docker_id"] = row.DockerHostContainerDockerID.String
		}
		items = append(items, item)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"alert_rules": items})
}

// Delete handles DELETE /api/alert-rules/:id (Admin-only).
func (h *AlertRulesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireAdminActor(w, r)
	if !ok {
		return
	}
	ruleID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "alert rule not found")
		return
	}
	if err := h.rules.Delete(r.Context(), ruleID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to delete alert rule")
		return
	}
	_ = h.audit.Log(r.Context(), services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditAlertRuleDeleted, ResourceType: "ALERT_RULE", ResourceID: &ruleID,
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func requireAdminActor(w http.ResponseWriter, r *http.Request) (services.AuthenticatedUser, bool) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return services.AuthenticatedUser{}, false
	}
	if !user.IsAdmin() {
		httpx.WriteError(w, http.StatusForbidden, "Admin only")
		return services.AuthenticatedUser{}, false
	}
	return user, true
}

func writeAlertRuleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, services.ErrAlertRuleNotFound):
		httpx.WriteError(w, http.StatusNotFound, "alert rule not found")
	case errors.Is(err, services.ErrAlertRuleResourceNotFound):
		httpx.WriteError(w, http.StatusNotFound, "resource not found")
	case errors.Is(err, services.ErrAlertRuleInvalidType), errors.Is(err, services.ErrAlertRuleInvalidCondition), errors.Is(err, services.ErrAlertRuleInvalidSeverity):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	default:
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
	}
}
