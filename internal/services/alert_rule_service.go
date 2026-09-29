package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// float8OrNil converts an optional recovery threshold to pgtype.Float8 --
// NULL means "no hysteresis gap" (AlertEngine falls back to the trigger
// threshold itself), never a fabricated 0.
func float8OrNil(v *float64) pgtype.Float8 {
	if v == nil {
		return pgtype.Float8{}
	}
	return pgutil.Float8(*v)
}

var (
	ErrAlertRuleInvalidType      = errors.New("invalid alert type")
	ErrAlertRuleInvalidCondition = errors.New("invalid condition")
	ErrAlertRuleInvalidSeverity  = errors.New("invalid severity")
	ErrAlertRuleNotFound         = errors.New("alert rule not found")
	ErrAlertRuleResourceNotFound = errors.New("resource not found")
)

// AlertRuleService is the Admin-only CRUD layer for alert rules (spec
// §8/§33). Every rule is validated against the closed AlertTemplates
// catalog -- there is no way to save a rule with a made-up alert_type/
// metric pairing (spec §37/§38's "no arbitrary code from alert rules").
type AlertRuleService struct {
	store *repository.Store
}

// NewAlertRuleService creates an AlertRuleService.
func NewAlertRuleService(store *repository.Store) *AlertRuleService {
	return &AlertRuleService{store: store}
}

func findTemplate(alertType AlertType) (AlertTemplate, bool) {
	for _, t := range AlertTemplates {
		if t.Type == alertType {
			return t, true
		}
	}
	return AlertTemplate{}, false
}

var validConditions = map[AlertCondition]bool{
	CondGreaterThan: true, CondLessThan: true, CondGreaterThanOrEqual: true, CondLessThanOrEqual: true, CondEqual: true,
}
var validSeverities = map[AlertSeverity]bool{AlertSeverityInfo: true, AlertSeverityWarning: true, AlertSeverityCritical: true}

// CreateRuleInput is POST /api/alert-rules's request shape.
type CreateRuleInput struct {
	ResourceID                    uuid.UUID
	ContainerID                   *uuid.UUID
	K8sPodID                      *uuid.UUID
	DockerHostContainerSightingID *uuid.UUID
	AlertType                     AlertType
	Condition                     AlertCondition
	Threshold                     float64
	RecoveryThreshold             *float64
	DurationSeconds               int32
	Severity                      AlertSeverity
	NotificationPolicyID          *uuid.UUID
	Enabled                       bool
}

// Create validates alertType against the template catalog (which also
// pins its required metric -- never client-supplied) and that the target
// resource actually exists, then persists the rule.
func (s *AlertRuleService) Create(ctx context.Context, in CreateRuleInput, actorID uuid.UUID) (generated.AlertRule, error) {
	template, ok := findTemplate(in.AlertType)
	if !ok {
		return generated.AlertRule{}, ErrAlertRuleInvalidType
	}
	if !validConditions[in.Condition] {
		return generated.AlertRule{}, ErrAlertRuleInvalidCondition
	}
	if !validSeverities[in.Severity] {
		return generated.AlertRule{}, ErrAlertRuleInvalidSeverity
	}
	resource, err := s.store.GetResourceByID(ctx, in.ResourceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.AlertRule{}, ErrAlertRuleResourceNotFound
		}
		return generated.AlertRule{}, fmt.Errorf("load resource: %w", err)
	}
	if resource.DeletedAt.Valid {
		return generated.AlertRule{}, ErrAlertRuleResourceNotFound
	}
	// Special-cased sub-target categories (a rule narrowed to one Docker
	// container/K8s pod/Docker Host container under a parent resource) vs.
	// every other category, which must match the resource's own type
	// directly -- DOCKER_CONTAINER was the original precedent (migration
	// 025); K8S_POD/DOCKER_HOST_CONTAINER (migration 058) mirror it exactly.
	switch template.AppliesToResource {
	case "DOCKER_CONTAINER":
		if resource.ResourceType != "VM" || in.ContainerID == nil {
			return generated.AlertRule{}, fmt.Errorf("%w: %s requires a VM resource and a container_id", ErrAlertRuleInvalidType, in.AlertType)
		}
	case "K8S_POD":
		if resource.ResourceType != "K8S_CLUSTER" || in.K8sPodID == nil {
			return generated.AlertRule{}, fmt.Errorf("%w: %s requires a K8S_CLUSTER resource and a k8s_pod_id", ErrAlertRuleInvalidType, in.AlertType)
		}
	case "DOCKER_HOST_CONTAINER":
		if resource.ResourceType != "DOCKER_HOST" || in.DockerHostContainerSightingID == nil {
			return generated.AlertRule{}, fmt.Errorf("%w: %s requires a DOCKER_HOST resource and a docker_host_container_sighting_id", ErrAlertRuleInvalidType, in.AlertType)
		}
	default:
		if resource.ResourceType != template.AppliesToResource {
			return generated.AlertRule{}, fmt.Errorf("%w: %s applies to %s resources, not %s", ErrAlertRuleInvalidType, in.AlertType, template.AppliesToResource, resource.ResourceType)
		}
	}

	rule, err := s.store.CreateAlertRule(ctx, generated.CreateAlertRuleParams{
		ResourceID: in.ResourceID, ContainerID: pgutil.NullUUID(in.ContainerID),
		K8sPodID: pgutil.NullUUID(in.K8sPodID), DockerHostContainerSightingID: pgutil.NullUUID(in.DockerHostContainerSightingID),
		AlertType: string(in.AlertType),
		Metric:    string(template.Metric), Condition: string(in.Condition), Threshold: in.Threshold, RecoveryThreshold: float8OrNil(in.RecoveryThreshold),
		DurationSeconds: in.DurationSeconds, Severity: string(in.Severity), NotificationPolicyID: pgutil.NullUUID(in.NotificationPolicyID),
		Enabled: in.Enabled, CreatedBy: pgutil.NullUUID(&actorID),
	})
	if err != nil {
		return generated.AlertRule{}, fmt.Errorf("create alert rule: %w", err)
	}
	return rule, nil
}

// UpdateRuleInput is PUT /api/alert-rules/:id's request shape -- the
// alert_type/metric/resource/container are fixed at creation (spec's
// worked example never shows editing what a rule monitors, only its
// thresholds/severity/policy/enabled state); to monitor something
// different, create a new rule.
type UpdateRuleInput struct {
	Condition            AlertCondition
	Threshold            float64
	RecoveryThreshold    *float64
	DurationSeconds      int32
	Severity             AlertSeverity
	NotificationPolicyID *uuid.UUID
	Enabled              bool
}

func (s *AlertRuleService) Update(ctx context.Context, ruleID uuid.UUID, in UpdateRuleInput) (generated.AlertRule, error) {
	if !validConditions[in.Condition] {
		return generated.AlertRule{}, ErrAlertRuleInvalidCondition
	}
	if !validSeverities[in.Severity] {
		return generated.AlertRule{}, ErrAlertRuleInvalidSeverity
	}
	updated, err := s.store.UpdateAlertRule(ctx, generated.UpdateAlertRuleParams{
		ID: ruleID, Condition: string(in.Condition), Threshold: in.Threshold, RecoveryThreshold: float8OrNil(in.RecoveryThreshold),
		DurationSeconds: in.DurationSeconds, Severity: string(in.Severity), NotificationPolicyID: pgutil.NullUUID(in.NotificationPolicyID),
		Enabled: in.Enabled,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.AlertRule{}, ErrAlertRuleNotFound
		}
		return generated.AlertRule{}, fmt.Errorf("update alert rule: %w", err)
	}
	return updated, nil
}

func (s *AlertRuleService) Get(ctx context.Context, ruleID uuid.UUID) (generated.AlertRule, error) {
	rule, err := s.store.GetAlertRuleByID(ctx, ruleID)
	if err != nil {
		return generated.AlertRule{}, ErrAlertRuleNotFound
	}
	return rule, nil
}

func (s *AlertRuleService) Delete(ctx context.Context, ruleID uuid.UUID) error {
	if err := s.store.DeleteAlertRule(ctx, ruleID); err != nil {
		return fmt.Errorf("delete alert rule: %w", err)
	}
	return nil
}

// Suppress temporarily silences a rule (spec §30): no new alert is
// created while suppressed_until is in the future, and any currently
// open alert transitions to SUPPRESSED (AlertEngine.ensureRuleSuppressed
// does the transition on its next cycle, never here synchronously --
// keeps this call fast and lets the engine's own audited transition be
// the single place that happens).
func (s *AlertRuleService) Suppress(ctx context.Context, ruleID uuid.UUID, until time.Time, reason string, actorID uuid.UUID) (generated.AlertRule, error) {
	rule, err := s.store.SuppressAlertRule(ctx, generated.SuppressAlertRuleParams{
		ID: ruleID, SuppressedUntil: pgutil.Timestamptz(until), SuppressedReason: pgutil.Text(reason), SuppressedBy: pgutil.NullUUID(&actorID),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.AlertRule{}, ErrAlertRuleNotFound
		}
		return generated.AlertRule{}, fmt.Errorf("suppress alert rule: %w", err)
	}
	return rule, nil
}
