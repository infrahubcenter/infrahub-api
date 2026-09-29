package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

var (
	ErrAlertNotFound  = errors.New("alert not found")
	ErrAlertNotActive = errors.New("alert is not currently active")
	ErrAlertNotOpen   = errors.New("alert is not currently active or acknowledged")
)

// AlertService is the read/lifecycle-action layer for alerts (list/get/
// acknowledge/history) -- rule evaluation itself lives in AlertEngine;
// this only ever transitions an already-created alert, never invents a
// new state (spec §13: acknowledging "does NOT mean the problem is
// fixed").
type AlertService struct {
	store *repository.Store
	audit *AuditService
}

// NewAlertService creates an AlertService.
func NewAlertService(store *repository.Store, audit *AuditService) *AlertService {
	return &AlertService{store: store, audit: audit}
}

// Acknowledge records that an Admin has seen an ACTIVE alert -- never
// changes any infrastructure state, never implies the underlying
// condition is resolved (spec §13/§64).
func (s *AlertService) Acknowledge(ctx context.Context, alertID, actorID uuid.UUID) (generated.Alert, error) {
	updated, err := s.store.AcknowledgeAlert(ctx, generated.AcknowledgeAlertParams{ID: alertID, AcknowledgedBy: pgutil.NullUUID(&actorID)})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if _, getErr := s.store.GetAlertByID(ctx, alertID); getErr != nil {
				return generated.Alert{}, ErrAlertNotFound
			}
			return generated.Alert{}, ErrAlertNotActive
		}
		return generated.Alert{}, fmt.Errorf("acknowledge alert: %w", err)
	}
	_, _ = s.store.AppendAlertEvent(ctx, generated.AppendAlertEventParams{
		AlertID: alertID, EventType: "ACKNOWLEDGED", Status: string(AlertStatusAcknowledged), ActorID: pgutil.NullUUID(&actorID),
	})
	_ = s.audit.Log(ctx, AuditEvent{
		UserID: &actorID, Action: AuditAlertAcknowledged, ResourceType: "ALERT", ResourceID: &alertID,
	})
	return updated, nil
}

// Suppress silences an individual firing alert for a fixed duration
// (spec §30's worked example -- "Suppress CPU Alert, Duration: 2 hours,
// Reason: Planned maintenance"): the alert itself transitions to
// SUPPRESSED immediately, and its underlying rule is suppressed for the
// same window so the engine doesn't just recreate an identical alert on
// its very next evaluation cycle. Always audited with who/reason/when
// (spec §30/§55).
func (s *AlertService) Suppress(ctx context.Context, alertID uuid.UUID, duration time.Duration, reason string, actorID uuid.UUID) (generated.Alert, error) {
	alert, err := s.store.GetAlertByID(ctx, alertID)
	if err != nil {
		return generated.Alert{}, ErrAlertNotFound
	}
	if AlertStatus(alert.Status) != AlertStatusActive && AlertStatus(alert.Status) != AlertStatusAcknowledged {
		return generated.Alert{}, ErrAlertNotOpen
	}

	until := time.Now().Add(duration)
	if _, err := s.store.SuppressAlertRule(ctx, generated.SuppressAlertRuleParams{
		ID: alert.AlertRuleID, SuppressedUntil: pgutil.Timestamptz(until), SuppressedReason: pgutil.Text(reason), SuppressedBy: pgutil.NullUUID(&actorID),
	}); err != nil {
		return generated.Alert{}, fmt.Errorf("suppress alert rule: %w", err)
	}

	updated, err := s.store.SuppressAlert(ctx, generated.SuppressAlertParams{ID: alertID, SuppressedReason: pgutil.Text(reason)})
	if err != nil {
		return generated.Alert{}, fmt.Errorf("suppress alert: %w", err)
	}
	_, _ = s.store.AppendAlertEvent(ctx, generated.AppendAlertEventParams{
		AlertID: alertID, EventType: "SUPPRESSED", Status: string(AlertStatusSuppressed), Message: pgutil.Text(reason), ActorID: pgutil.NullUUID(&actorID),
	})
	_ = s.audit.Log(ctx, AuditEvent{
		UserID: &actorID, Action: AuditAlertSuppressed, ResourceType: "ALERT", ResourceID: &alertID,
		Metadata: map[string]any{"reason": reason, "until": until, "alert_rule_id": alert.AlertRuleID},
	})
	return updated, nil
}

// GetUserAlertAccessResourceIDs merges VM, database, object storage, and
// Docker/K8s-monitoring-grant resource access (spec §22: an alert is
// visible under the same rules its underlying resource already is) --
// mirrors RecommendationHandler.List's identical merge, just as a
// reusable service method since AlertService needs it in more than one
// handler method. Object storage was missing here until a prior fix,
// which meant a Member with legitimate object storage access could never
// see that resource's alerts or recommendations (under-reporting, never a
// leak, but still a bug: Object Storage alert types and recommendations
// have been generated since Step 17).
//
// docker_access_grants (docker.monitor/k8s.monitor) is unioned in for the
// new Dashboard feature (Folder > Dashboard): a Dashboard's only access
// model is that grant system, not vm.view/resource_permissions, so
// without this a Member whose sole grant is docker.monitor on a VM would
// open that Dashboard's Alerts tab and see it wrongly empty even though
// the underlying VM does have alerts.
func GetUserAlertAccessResourceIDs(ctx context.Context, authz *AuthorizationService, user AuthenticatedUser) ([]uuid.UUID, error) {
	vmAccess, err := authz.GetUserVMAccess(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("list vm access: %w", err)
	}
	dbAccess, err := authz.GetUserDatabaseAccess(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("list database access: %w", err)
	}
	objectStorageAccess, err := authz.GetUserObjectStorageAccess(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("list object storage access: %w", err)
	}
	dockerMonitorVMIDs, err := authz.AccessibleVMResourceIDsForDockerFeature(ctx, user, PermDockerMonitor)
	if err != nil {
		return nil, fmt.Errorf("list docker.monitor vm access: %w", err)
	}
	k8sMonitorClusterIDs, err := authz.AccessibleK8sClusterResourceIDsForFeature(ctx, user, PermK8sMonitor)
	if err != nil {
		return nil, fmt.Errorf("list k8s.monitor cluster access: %w", err)
	}
	ids := make([]uuid.UUID, 0, len(vmAccess)+len(dbAccess)+len(objectStorageAccess)+len(dockerMonitorVMIDs)+len(k8sMonitorClusterIDs))
	for _, a := range vmAccess {
		ids = append(ids, a.ResourceID)
	}
	for _, a := range dbAccess {
		ids = append(ids, a.ResourceID)
	}
	for _, a := range objectStorageAccess {
		ids = append(ids, a.ResourceID)
	}
	ids = append(ids, dockerMonitorVMIDs...)
	ids = append(ids, k8sMonitorClusterIDs...)
	return ids, nil
}
