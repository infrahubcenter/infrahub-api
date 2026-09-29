package services

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// NotificationService routes one alert event to every authorized
// recipient over every channel its resolved policy names (spec §28:
// "Database Critical -> Notification Policy -> Admin users authorized
// for database -> In-App notification. Do not notify unauthorized
// users."). It never decides *whether* an alert fired -- AlertEngine
// does that; this only fans an already-decided alert out to people.
type NotificationService struct {
	store      *repository.Store
	audit      *AuditService
	providers  map[NotificationChannel]NotificationProvider
	cooldown   time.Duration
	maxRetries int
	logger     *slog.Logger
}

// EmailConfig is NewNotificationService's SMTP settings -- see
// config.SMTPHost's doc comment for what an empty Host means.
type EmailConfig struct {
	Host      string
	Port      int32
	Username  string
	Password  string
	FromEmail string
	UseTLS    bool
	Timeout   time.Duration
}

// NewNotificationService creates a NotificationService with every
// NotificationChannel's provider registered -- IN_APP (trivial),
// WEBHOOK/SLACK/TEAMS (each an HTTP POST to a policy-configured URL), and
// EMAIL (SMTP, see EmailConfig -- delivery simply fails clearly if SMTP
// isn't configured, rather than the backend refusing to start).
func NewNotificationService(store *repository.Store, audit *AuditService, cooldown time.Duration, webhookTimeout time.Duration, maxRetries int, email EmailConfig, logger *slog.Logger) *NotificationService {
	if logger == nil {
		logger = slog.Default()
	}
	s := &NotificationService{
		store: store, audit: audit, providers: map[NotificationChannel]NotificationProvider{},
		cooldown: cooldown, maxRetries: maxRetries, logger: logger,
	}
	s.RegisterProvider(InAppProvider{})
	s.RegisterProvider(NewWebhookProvider(webhookTimeout))
	s.RegisterProvider(NewSlackProvider(webhookTimeout))
	s.RegisterProvider(NewTeamsProvider(webhookTimeout))
	s.RegisterProvider(NewEmailProvider(email.Host, email.Port, email.Username, email.Password, email.FromEmail, email.UseTLS, email.Timeout))
	return s
}

// RegisterProvider wires in a NotificationProvider for its channel --
// the extensibility seam spec §26 describes (future EmailProvider/
// SlackProvider/TeamsProvider register here, nothing else changes).
func (s *NotificationService) RegisterProvider(p NotificationProvider) {
	s.providers[p.Channel()] = p
}

// ErrNotificationChannelUnregistered means the requested channel has no
// provider at all (should be unreachable in practice -- NewNotificationService
// registers all five -- but kept as a defensive, clearly-worded error
// rather than a nil-pointer panic if that ever changes).
var ErrNotificationChannelUnregistered = fmt.Errorf("no notification provider registered for that channel")

// SendTest sends exactly one synthetic notification over channel right
// now, bypassing dedup/cooldown/retry entirely (this is an explicit,
// one-off admin action, not a real alert) and never touching the
// notifications table -- so an admin repeatedly testing their Slack/Teams
// URL while getting it right doesn't leave a trail of fake alert history.
// recipientEmail is only used by EMAIL (the admin's own account address,
// so they can confirm delivery); every other channel ignores it and posts
// to the policy's own configured URL instead.
func (s *NotificationService) SendTest(ctx context.Context, channel NotificationChannel, policy generated.NotificationPolicy, recipientEmail string) error {
	provider, ok := s.providers[channel]
	if !ok {
		return ErrNotificationChannelUnregistered
	}
	payload := NotificationPayload{
		AlertID: uuid.New(), Severity: AlertSeverityInfo, Status: AlertStatusActive,
		ResourceName: "Test Resource", ResourceType: "TEST", AlertType: "test_notification",
		Title: "Test notification from InfraHub", Body: fmt.Sprintf("This confirms the %s channel on notification policy %q is configured correctly.", channel, policy.Name),
		Timestamp: time.Now(), RecipientEmail: recipientEmail, WebhookURL: policy.WebhookUrl.String,
		SlackWebhookURL: policy.SlackWebhookUrl.String, TeamsWebhookURL: policy.TeamsWebhookUrl.String,
	}
	if err := provider.Validate(payload); err != nil {
		return err
	}
	return provider.Send(ctx, payload)
}

// DispatchInput is everything NotifyAlert needs about the firing alert
// and its resolved policy -- built by AlertEngine from data it already
// has, never re-queried here.
type DispatchInput struct {
	Alert           generated.Alert
	ResourceName    string
	ResourceType    string
	Channels        []NotificationChannel
	WebhookURL      string
	SlackWebhookURL string
	TeamsWebhookURL string
	CurrentValue    *float64
}

// categoryFor maps a firing alert to a notification-center category
// (spec §21).
func categoryFor(severity AlertSeverity, resourceType string) NotificationCategory {
	if severity == AlertSeverityCritical {
		return CategoryCriticalAlert
	}
	switch resourceType {
	case "VM":
		return CategoryVMEvent
	case "DATABASE":
		return CategoryDatabaseEvent
	default:
		return CategoryWarning
	}
}

// NotifyAlert fans one alert event out to every authorized recipient
// over every channel in in.Channels, honoring per-(alert, channel,
// recipient) cooldown (spec §44/§45) so an ongoing condition doesn't
// spam. Admins always receive every alert (mirrors the unconditional
// Admin bypass everywhere else in this project); Members only if they
// hold a direct grant or reach the resource via group membership (spec
// §22: "Members must receive notifications only for resources they are
// authorized to see").
func (s *NotificationService) NotifyAlert(ctx context.Context, in DispatchInput) {
	recipients, err := s.resolveRecipients(ctx, in.Alert.ResourceID)
	if err != nil {
		s.logger.Error("notification: failed to resolve recipients", "alert_id", in.Alert.ID, "error", err)
		return
	}
	category := categoryFor(AlertSeverity(in.Alert.Severity), in.ResourceType)

	// Step 21: per-recipient personal preference (Settings' Notification
	// Preferences) -- muted is looked up per-category, per-user, and
	// applied only to per-recipient channels below, never to the single
	// shared WEBHOOK dispatch above (a policy-level channel with no
	// concept of "recipient" to mute for). A lookup failure fails open
	// (nobody muted) rather than silently dropping a real notification --
	// this is a personal convenience feature, not a safety gate.
	muted, err := s.mutedRecipientsForCategory(ctx, recipients, category)
	if err != nil {
		s.logger.Error("notification: failed to resolve muted preferences", "alert_id", in.Alert.ID, "error", err)
		muted = nil
	}

	for _, channel := range in.Channels {
		// WEBHOOK/SLACK/TEAMS are each a single shared destination the
		// policy configures (a channel/URL, not a person) -- one delivery
		// per alert event, never fanned out per recipient the way IN_APP/
		// EMAIL are.
		if channel == ChannelWebhook || channel == ChannelSlack || channel == ChannelTeams {
			s.dispatchOne(ctx, in, channel, category, nil)
			continue
		}
		for _, userID := range recipients {
			if muted[userID] {
				continue
			}
			id := userID
			s.dispatchOne(ctx, in, channel, category, &id)
		}
	}
}

// mutedRecipientsForCategory returns the subset of recipients who have
// muted category in their personal preferences (Step 21). CRITICAL_ALERT
// never appears here -- UserPreferencesService rejects muting it at write
// time, so a critical alert always still reaches every recipient this
// function is even asked about, with no special-case needed here.
func (s *NotificationService) mutedRecipientsForCategory(ctx context.Context, recipients []uuid.UUID, category NotificationCategory) (map[uuid.UUID]bool, error) {
	if len(recipients) == 0 {
		return nil, nil
	}
	rows, err := s.store.Queries.GetMutedNotificationCategoriesForUsers(ctx, recipients)
	if err != nil {
		return nil, fmt.Errorf("load muted notification categories: %w", err)
	}
	muted := make(map[uuid.UUID]bool, len(rows))
	for _, row := range rows {
		for _, c := range row.MutedNotificationCategories {
			if c == string(category) {
				muted[row.UserID] = true
				break
			}
		}
	}
	return muted, nil
}

func (s *NotificationService) resolveRecipients(ctx context.Context, resourceID uuid.UUID) ([]uuid.UUID, error) {
	admins, err := s.store.ListAdminUserIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list admin users: %w", err)
	}
	members, err := s.store.ListAuthorizedMemberUserIDsForResource(ctx, resourceID)
	if err != nil {
		return nil, fmt.Errorf("list authorized member users: %w", err)
	}
	seen := map[uuid.UUID]bool{}
	result := make([]uuid.UUID, 0, len(admins)+len(members))
	for _, id := range admins {
		if !seen[id] {
			seen[id] = true
			result = append(result, id)
		}
	}
	for _, id := range members {
		if !seen[id] {
			seen[id] = true
			result = append(result, id)
		}
	}
	return result, nil
}

func (s *NotificationService) dispatchOne(
	ctx context.Context, in DispatchInput, channel NotificationChannel, category NotificationCategory,
	recipientUserID *uuid.UUID,
) {
	since := time.Now().Add(-s.cooldown)
	if existing, err := s.store.GetRecentNotificationForDedup(ctx, generated.GetRecentNotificationForDedupParams{
		AlertID: pgutil.NullUUID(&in.Alert.ID), Channel: string(channel), UserID: pgutil.NullUUID(recipientUserID), CreatedAt: pgutil.Timestamptz(since),
	}); err == nil {
		_ = existing
		return // already notified this recipient/channel within the cooldown window
	}

	provider, ok := s.providers[channel]
	status := "FAILED"
	var errMsg string
	attempts := 0

	if !ok {
		errMsg = fmt.Sprintf("no notification provider registered for channel %s", channel)
	} else {
		var recipientEmail string
		if channel == ChannelEmail && recipientUserID != nil {
			if user, err := s.store.GetUserByID(ctx, *recipientUserID); err == nil {
				recipientEmail = user.Email
			} else {
				s.logger.Warn("notification: failed to resolve recipient email", "user_id", *recipientUserID, "error", err)
			}
		}
		payload := NotificationPayload{
			AlertID: in.Alert.ID, Severity: AlertSeverity(in.Alert.Severity), Status: AlertStatus(in.Alert.Status),
			ResourceName: in.ResourceName, ResourceType: in.ResourceType, AlertType: in.Alert.AlertType,
			Title: in.Alert.Title, Body: pgutil.TextOrEmpty(in.Alert.Description), CurrentValue: in.CurrentValue,
			Threshold: in.Alert.Threshold, Timestamp: time.Now(), RecipientUserID: recipientUserID,
			RecipientEmail: recipientEmail, WebhookURL: in.WebhookURL, SlackWebhookURL: in.SlackWebhookURL,
			TeamsWebhookURL: in.TeamsWebhookURL,
		}
		status, errMsg, attempts = s.sendWithRetry(ctx, provider, payload)
	}

	title := in.Alert.Title
	body := pgutil.TextOrEmpty(in.Alert.Description)
	severity := in.Alert.Severity
	notif, err := s.store.CreateNotification(ctx, generated.CreateNotificationParams{
		AlertID: pgutil.NullUUID(&in.Alert.ID), UserID: pgutil.NullUUID(recipientUserID), Category: string(category),
		Channel: string(channel), Severity: pgutil.Text(severity), Title: title, Body: pgutil.Text(body),
		Status: status, ErrorMessage: pgutil.Text(errMsg), AttemptCount: int32(attempts),
	})
	if err != nil {
		s.logger.Error("notification: failed to persist delivery record", "alert_id", in.Alert.ID, "channel", channel, "error", err)
		return
	}
	if notif.Status == "FAILED" {
		_ = s.audit.Log(ctx, AuditEvent{
			Action: AuditNotificationFailed, ResourceType: "ALERT", ResourceID: &in.Alert.ID,
			Metadata: map[string]any{"notification_id": notif.ID, "channel": string(channel), "error": errMsg},
		})
	} else {
		_ = s.audit.Log(ctx, AuditEvent{
			Action: AuditNotificationSent, ResourceType: "ALERT", ResourceID: &in.Alert.ID,
			Metadata: map[string]any{"notification_id": notif.ID, "channel": string(channel)},
		})
	}
	_ = s.store.SetAlertLastNotifiedAt(ctx, generated.SetAlertLastNotifiedAtParams{ID: in.Alert.ID, LastNotifiedAt: pgutil.Timestamptz(time.Now())})
}

// sendWithRetry retries a transient failure a bounded number of times
// with a short fixed backoff (spec §54: "controlled backoff... do not
// retry indefinitely") -- never retries a validation failure (a
// misconfigured webhook URL will never succeed no matter how many times
// it's attempted).
func (s *NotificationService) sendWithRetry(ctx context.Context, provider NotificationProvider, payload NotificationPayload) (status, errMsg string, attempts int) {
	if err := provider.Validate(payload); err != nil {
		return "FAILED", err.Error(), 1
	}
	backoff := 500 * time.Millisecond
	for attempt := 1; attempt <= s.maxRetries; attempt++ {
		attempts = attempt
		if err := provider.Send(ctx, payload); err != nil {
			errMsg = err.Error()
			if attempt == s.maxRetries {
				break
			}
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return "FAILED", ctx.Err().Error(), attempts
			}
			backoff *= 2
			continue
		}
		return "SENT", "", attempts
	}
	return "FAILED", errMsg, attempts
}
