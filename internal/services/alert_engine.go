package services

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// AlertEngine is Step 16's central evaluation loop (spec §36):
// Metrics -> Rule Evaluation -> Threshold -> Duration -> Deduplication ->
// Alert State -> Notification. It never collects a metric itself (that
// remains each existing scheduler's job, Steps 6/8/13 unchanged) and
// never executes any remediation (spec §63) -- an alert only reaches a
// human, never a command.
type AlertEngine struct {
	store          *repository.Store
	audit          *AuditService
	notifications  *NotificationService
	dockerAgentHub *DockerAgentHub
	k8sAgentHub    *K8sAgentHub
	logger         *slog.Logger

	// Engine health is tracked independently of monitoring/alert outcome
	// (spec §52: "If alert evaluation fails: Monitoring must continue...
	// Do not mark VM/database unavailable just because alert evaluation
	// failed") -- a failed evaluation cycle degrades this flag, never any
	// resource's own health.
	degraded  atomic.Bool
	lastError atomic.Pointer[string]
	lastRunAt atomic.Pointer[time.Time]
}

// NewAlertEngine creates an AlertEngine. dockerAgentHub/k8sAgentHub back
// the new DOCKER_HOST_UNAVAILABLE/K8S_CLUSTER_UNAVAILABLE metrics (Alert
// Rules widening) -- a plain in-memory IsConnected check, no query.
func NewAlertEngine(store *repository.Store, audit *AuditService, notifications *NotificationService, dockerAgentHub *DockerAgentHub, k8sAgentHub *K8sAgentHub, logger *slog.Logger) *AlertEngine {
	if logger == nil {
		logger = slog.Default()
	}
	return &AlertEngine{store: store, audit: audit, notifications: notifications, dockerAgentHub: dockerAgentHub, k8sAgentHub: k8sAgentHub, logger: logger}
}

// EngineStatus reports the alert engine's own operational health (spec
// §52's "Alert Engine: Degraded" display) -- separate from any
// resource's monitoring health.
type EngineStatus struct {
	Healthy   bool
	LastError string
	LastRunAt *time.Time
}

// Status returns the engine's current health.
func (e *AlertEngine) Status() EngineStatus {
	status := EngineStatus{Healthy: !e.degraded.Load()}
	if p := e.lastError.Load(); p != nil {
		status.LastError = *p
	}
	if p := e.lastRunAt.Load(); p != nil {
		status.LastRunAt = p
	}
	return status
}

// Run starts the periodic evaluation loop and blocks until ctx is
// cancelled.
func (e *AlertEngine) Run(ctx context.Context, interval time.Duration) {
	e.EvaluateOnce(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.EvaluateOnce(ctx)
		}
	}
}

// EvaluateOnce runs exactly one evaluation cycle across every enabled
// rule. A panic or a failure to even list rules degrades the engine's
// own status but never propagates -- callers (the scheduler, or a test
// calling this directly) always get a clean return.
func (e *AlertEngine) EvaluateOnce(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			e.markDegraded(fmt.Sprintf("panic during evaluation: %v", r))
		}
	}()

	rules, err := e.store.ListEnabledAlertRulesForEvaluation(ctx)
	if err != nil {
		e.markDegraded(fmt.Sprintf("failed to list alert rules: %v", err))
		return
	}

	lookup := newAlertMetricLookup(e.store, e.dockerAgentHub, e.k8sAgentHub)
	policyCache := map[uuid.UUID]*generated.NotificationPolicy{}
	for _, rule := range rules {
		e.evaluateRule(ctx, rule, lookup, policyCache)
	}
	e.markHealthy()
}

func (e *AlertEngine) markDegraded(msg string) {
	e.degraded.Store(true)
	e.lastError.Store(&msg)
	now := time.Now()
	e.lastRunAt.Store(&now)
	e.logger.Error("alert engine evaluation cycle failed", "error", msg)
}

func (e *AlertEngine) markHealthy() {
	e.degraded.Store(false)
	e.lastError.Store(nil)
	now := time.Now()
	e.lastRunAt.Store(&now)
}

func (e *AlertEngine) evaluateRule(
	ctx context.Context, row generated.ListEnabledAlertRulesForEvaluationRow,
	lookup *alertMetricLookup, policyCache map[uuid.UUID]*generated.NotificationPolicy,
) {
	now := time.Now()

	if row.SuppressedUntil.Valid {
		if row.SuppressedUntil.Time.After(now) {
			e.ensureRuleSuppressed(ctx, row)
			return
		}
		_, _ = e.store.ClearAlertRuleSuppression(ctx, row.ID)
	}

	sample := lookup.Resolve(ctx, row)
	if !sample.Available {
		return // no data yet -- never flap a rule on missing data (never fabricate a metric)
	}

	condition := AlertCondition(row.Condition)
	breaching := condition.Evaluate(sample.Value, row.Threshold)

	existing, err := e.store.GetActiveAlertForRule(ctx, row.ID)
	hasExisting := err == nil

	if hasExisting {
		e.evaluateExistingAlert(ctx, row, existing, sample, condition, policyCache)
		return
	}
	if err != nil && err != pgx.ErrNoRows {
		e.logger.Error("alert engine: failed to load active alert", "rule_id", row.ID, "error", err)
		return
	}

	if !breaching {
		if row.BreachStartedAt.Valid {
			e.store.SetAlertRuleBreachStartedAt(ctx, generated.SetAlertRuleBreachStartedAtParams{ID: row.ID}) //nolint:errcheck -- best-effort state clear
		}
		return
	}

	// Duration requirement (spec §9): a single bad sample never triggers
	// unless duration_seconds is 0.
	if !row.BreachStartedAt.Valid {
		_ = e.store.SetAlertRuleBreachStartedAt(ctx, generated.SetAlertRuleBreachStartedAtParams{ID: row.ID, BreachStartedAt: pgutil.Timestamptz(now)})
		if row.DurationSeconds > 0 {
			return
		}
	} else if now.Sub(row.BreachStartedAt.Time) < time.Duration(row.DurationSeconds)*time.Second {
		return
	}

	e.createAlert(ctx, row, sample, policyCache)
}

func (e *AlertEngine) evaluateExistingAlert(
	ctx context.Context, row generated.ListEnabledAlertRulesForEvaluationRow, alert generated.Alert,
	sample metricSample, condition AlertCondition, policyCache map[uuid.UUID]*generated.NotificationPolicy,
) {
	updated, err := e.store.UpdateAlertSample(ctx, generated.UpdateAlertSampleParams{ID: alert.ID, CurrentValue: pgutil.Float8(sample.Value)})
	if err != nil {
		e.logger.Error("alert engine: failed to update alert sample", "alert_id", alert.ID, "error", err)
		updated = alert
	}

	// Recovery / hysteresis (spec §10): resolve only once the recovery
	// condition -- the trigger condition's inverse, evaluated against
	// recovery_threshold when configured, else against the same
	// threshold -- actually holds. A single good sample after a long bad
	// streak resolves immediately by design; duration only gates
	// *triggering*, never recovery, matching spec §12's example flow.
	recoveryThreshold := row.Threshold
	if row.RecoveryThreshold.Valid {
		recoveryThreshold = row.RecoveryThreshold.Float64
	}
	if condition.Inverse().Evaluate(sample.Value, recoveryThreshold) {
		resolved, err := e.store.ResolveAlert(ctx, alert.ID)
		if err != nil {
			e.logger.Error("alert engine: failed to resolve alert", "alert_id", alert.ID, "error", err)
			return
		}
		e.appendEvent(ctx, resolved.ID, "RESOLVED", string(AlertStatusResolved), &sample.Value, row.Threshold, "Recovery condition met.", nil)
		_ = e.audit.Log(ctx, AuditEvent{
			Action: AuditAlertResolved, ResourceType: "ALERT", ResourceID: &resolved.ID,
			Metadata: map[string]any{"alert_rule_id": row.ID, "resource_id": row.ResourceID, "value": sample.Value},
		})
		_ = e.store.SetAlertRuleBreachStartedAt(ctx, generated.SetAlertRuleBreachStartedAtParams{ID: row.ID})
		return
	}

	e.appendEvent(ctx, updated.ID, "SAMPLE", updated.Status, &sample.Value, row.Threshold, "", nil)
	e.dispatchNotification(ctx, row, updated, sample.Value, policyCache)
}

func (e *AlertEngine) createAlert(
	ctx context.Context, row generated.ListEnabledAlertRulesForEvaluationRow, sample metricSample,
	policyCache map[uuid.UUID]*generated.NotificationPolicy,
) {
	title, description := alertTitleAndDescription(AlertType(row.AlertType), targetLabel(row), sample.Value, row.Threshold, AlertCondition(row.Condition))
	alert, err := e.store.CreateAlert(ctx, generated.CreateAlertParams{
		AlertRuleID: row.ID, ResourceID: row.ResourceID, ContainerID: row.ContainerID, WorkspaceID: pgutil.NullUUID(&row.WorkspaceID),
		AlertType: row.AlertType, Severity: row.Severity, Metric: row.Metric, CurrentValue: pgutil.Float8(sample.Value),
		Threshold: row.Threshold, Title: title, Description: pgutil.Text(description),
	})
	if err != nil {
		e.logger.Error("alert engine: failed to create alert", "rule_id", row.ID, "error", err)
		return
	}
	e.appendEvent(ctx, alert.ID, "CREATED", string(AlertStatusActive), &sample.Value, row.Threshold, "Duration and threshold conditions met.", nil)
	_ = e.audit.Log(ctx, AuditEvent{
		Action: AuditAlertCreated, ResourceType: "ALERT", ResourceID: &alert.ID,
		Metadata: map[string]any{"alert_rule_id": row.ID, "resource_id": row.ResourceID, "alert_type": row.AlertType, "severity": row.Severity, "value": sample.Value},
	})
	e.dispatchNotification(ctx, row, alert, sample.Value, policyCache)
}

// ensureRuleSuppressed transitions any currently-open alert for a
// suppressed rule to SUPPRESSED (spec §30/§31) -- never deletes it,
// never silently hides an alert that was already ACKNOWLEDGED by an
// Admin who is actively tracking it as anything other than what it
// actually is.
func (e *AlertEngine) ensureRuleSuppressed(ctx context.Context, row generated.ListEnabledAlertRulesForEvaluationRow) {
	open, err := e.store.ListNonTerminalAlertsForRule(ctx, row.ID)
	if err != nil || len(open) == 0 {
		return
	}
	reason := "Alert rule is suppressed."
	if row.SuppressedReason.Valid && row.SuppressedReason.String != "" {
		reason = row.SuppressedReason.String
	}
	for _, alert := range open {
		suppressed, err := e.store.SuppressAlert(ctx, generated.SuppressAlertParams{ID: alert.ID, SuppressedReason: pgutil.Text(reason)})
		if err != nil {
			continue
		}
		e.appendEvent(ctx, suppressed.ID, "SUPPRESSED", string(AlertStatusSuppressed), nil, alert.Threshold, reason, uuidPtr(row.SuppressedBy))
		_ = e.audit.Log(ctx, AuditEvent{
			Action: AuditAlertSuppressed, ResourceType: "ALERT", ResourceID: &suppressed.ID,
			Metadata: map[string]any{"alert_rule_id": row.ID, "reason": reason},
		})
	}
}

func (e *AlertEngine) appendEvent(ctx context.Context, alertID uuid.UUID, eventType, status string, value *float64, threshold float64, message string, actorID *uuid.UUID) {
	var valueParam pgtype.Float8
	if value != nil {
		valueParam = pgutil.Float8(*value)
	}
	_, _ = e.store.AppendAlertEvent(ctx, generated.AppendAlertEventParams{
		AlertID: alertID, EventType: eventType, Status: status, Value: valueParam, Threshold: pgutil.Float8(threshold),
		Message: pgutil.Text(message), ActorID: pgutil.NullUUID(actorID),
	})
}

// defaultPolicyCacheKey is a sentinel cache key for the system default
// policy -- distinguishable from any real notification_policies.id since
// gen_random_uuid() never produces the nil UUID.
var defaultPolicyCacheKey = uuid.Nil

func (e *AlertEngine) resolvePolicy(ctx context.Context, row generated.ListEnabledAlertRulesForEvaluationRow, cache map[uuid.UUID]*generated.NotificationPolicy) *generated.NotificationPolicy {
	if row.NotificationPolicyID.Valid {
		id := uuid.UUID(row.NotificationPolicyID.Bytes)
		if p, ok := cache[id]; ok {
			return p
		}
		if p, err := e.store.GetNotificationPolicyByID(ctx, id); err == nil {
			cache[id] = &p
			return &p
		}
	}
	if p, ok := cache[defaultPolicyCacheKey]; ok {
		return p
	}
	p, err := e.store.GetDefaultNotificationPolicy(ctx)
	if err != nil {
		cache[defaultPolicyCacheKey] = nil
		return nil
	}
	cache[defaultPolicyCacheKey] = &p
	return &p
}

func (e *AlertEngine) dispatchNotification(
	ctx context.Context, row generated.ListEnabledAlertRulesForEvaluationRow, alert generated.Alert, value float64,
	policyCache map[uuid.UUID]*generated.NotificationPolicy,
) {
	policy := e.resolvePolicy(ctx, row, policyCache)
	if policy == nil {
		return
	}
	channels := channelsForSeverity(*policy, AlertSeverity(alert.Severity))
	if len(channels) == 0 {
		return
	}
	e.notifications.NotifyAlert(ctx, DispatchInput{
		Alert: alert, ResourceName: row.ResourceName, ResourceType: row.ResourceType,
		Channels: channels, WebhookURL: policy.WebhookUrl.String, SlackWebhookURL: policy.SlackWebhookUrl.String,
		TeamsWebhookURL: policy.TeamsWebhookUrl.String, CurrentValue: &value,
	})
}

func channelsForSeverity(policy generated.NotificationPolicy, severity AlertSeverity) []NotificationChannel {
	var raw []string
	switch severity {
	case AlertSeverityCritical:
		raw = policy.CriticalChannels
	case AlertSeverityWarning:
		raw = policy.WarningChannels
	default:
		raw = policy.InfoChannels
	}
	channels := make([]NotificationChannel, 0, len(raw))
	for _, c := range raw {
		channels = append(channels, NotificationChannel(c))
	}
	return channels
}

// targetLabel is what alertTitleAndDescription uses in place of a bare
// resource name -- for a rule narrowed to one K8s pod or one Docker Host
// container (migration 058), the resource name alone (the cluster/host)
// would make every pod/container under it produce an identical,
// indistinguishable alert title. VM-scoped Docker containers keep the
// resource name alone, matching this engine's pre-existing behavior
// there (out of scope to change here).
func targetLabel(row generated.ListEnabledAlertRulesForEvaluationRow) string {
	if row.K8sPodID.Valid && row.K8sPodName.Valid {
		ns := row.K8sPodNamespace.String
		if ns != "" {
			return fmt.Sprintf("%s (%s/%s)", row.ResourceName, ns, row.K8sPodName.String)
		}
		return fmt.Sprintf("%s (%s)", row.ResourceName, row.K8sPodName.String)
	}
	if row.DockerHostContainerSightingID.Valid && row.DockerHostContainerDockerID.Valid && len(row.DockerHostContainerDockerID.String) >= 8 {
		return fmt.Sprintf("%s (container %s)", row.ResourceName, row.DockerHostContainerDockerID.String[:8])
	}
	return row.ResourceName
}

// alertTitleAndDescription renders a human-readable title/description
// from the rule's own configuration -- never a client-supplied string
// (spec §14's "Alert" field, always backend-generated).
func alertTitleAndDescription(alertType AlertType, resourceName string, value, threshold float64, condition AlertCondition) (title, description string) {
	label := string(alertType)
	for _, t := range AlertTemplates {
		if t.Type == alertType {
			label = t.Label
			break
		}
	}
	title = fmt.Sprintf("%s: %s", resourceName, label)
	description = fmt.Sprintf("%s (current: %.2f, threshold: %s %.2f).", label, value, condition, threshold)
	return title, description
}
