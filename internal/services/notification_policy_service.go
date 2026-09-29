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

var (
	ErrNotificationPolicyNotFound       = errors.New("notification policy not found")
	ErrNotificationPolicyInvalidChannel = errors.New("invalid notification channel")
)

var validChannels = map[NotificationChannel]bool{
	ChannelInApp: true, ChannelEmail: true, ChannelSlack: true, ChannelTeams: true, ChannelWebhook: true,
}

// NotificationPolicyService is the Admin-only CRUD layer for
// notification policies (spec §27): which channels fire per severity,
// plus optional quiet hours and up to three webhook-style destinations
// (generic WEBHOOK, Slack, Teams). Every channel a policy can select
// (IN_APP/EMAIL/SLACK/TEAMS/WEBHOOK) has a real provider registered -- see
// notification_provider.go.
type NotificationPolicyService struct {
	store *repository.Store
}

func NewNotificationPolicyService(store *repository.Store) *NotificationPolicyService {
	return &NotificationPolicyService{store: store}
}

func validateChannels(channels []string) error {
	for _, c := range channels {
		if !validChannels[NotificationChannel(c)] {
			return fmt.Errorf("%w: %s", ErrNotificationPolicyInvalidChannel, c)
		}
	}
	return nil
}

// PolicyInput is the create/update request shape.
type PolicyInput struct {
	Name               string
	InfoChannels       []string
	WarningChannels    []string
	CriticalChannels   []string
	QuietHoursStart    *string // "HH:MM"
	QuietHoursEnd      *string
	QuietHoursTimezone string
	WebhookURL         string
	// SlackWebhookURL/TeamsWebhookURL are each channel's own "Incoming
	// Webhook" URL (from a Slack app / a Teams connector) -- independent
	// of WebhookURL, which is the generic WEBHOOK channel's target. See
	// notification_provider.go's SlackProvider/TeamsProvider.
	SlackWebhookURL string
	TeamsWebhookURL string
}

func (s *NotificationPolicyService) Create(ctx context.Context, in PolicyInput, actorID uuid.UUID) (generated.NotificationPolicy, error) {
	if err := validateChannels(in.InfoChannels); err != nil {
		return generated.NotificationPolicy{}, err
	}
	if err := validateChannels(in.WarningChannels); err != nil {
		return generated.NotificationPolicy{}, err
	}
	if err := validateChannels(in.CriticalChannels); err != nil {
		return generated.NotificationPolicy{}, err
	}
	if err := validateOptionalWebhookURLs(in); err != nil {
		return generated.NotificationPolicy{}, err
	}
	policy, err := s.store.CreateNotificationPolicy(ctx, generated.CreateNotificationPolicyParams{
		Name: in.Name, IsDefault: false, InfoChannels: in.InfoChannels, WarningChannels: in.WarningChannels,
		CriticalChannels: in.CriticalChannels, QuietHoursStart: parseClockTime(in.QuietHoursStart),
		QuietHoursEnd: parseClockTime(in.QuietHoursEnd), QuietHoursTimezone: pgutil.Text(in.QuietHoursTimezone),
		WebhookUrl: pgutil.Text(in.WebhookURL), SlackWebhookUrl: pgutil.Text(in.SlackWebhookURL),
		TeamsWebhookUrl: pgutil.Text(in.TeamsWebhookURL), CreatedBy: pgutil.NullUUID(&actorID),
	})
	if err != nil {
		return generated.NotificationPolicy{}, fmt.Errorf("create notification policy: %w", err)
	}
	return policy, nil
}

// validateOptionalWebhookURLs applies validateWebhookURL's SSRF-hardening
// to each of the three independent webhook-style destinations a policy
// can carry -- each only checked when actually set (all three are
// optional; a policy might use none, one, or all of them).
func validateOptionalWebhookURLs(in PolicyInput) error {
	for _, url := range []string{in.WebhookURL, in.SlackWebhookURL, in.TeamsWebhookURL} {
		if url == "" {
			continue
		}
		if err := validateWebhookURL(url); err != nil {
			return err
		}
	}
	return nil
}

func (s *NotificationPolicyService) Update(ctx context.Context, id uuid.UUID, in PolicyInput) (generated.NotificationPolicy, error) {
	if err := validateChannels(in.InfoChannels); err != nil {
		return generated.NotificationPolicy{}, err
	}
	if err := validateChannels(in.WarningChannels); err != nil {
		return generated.NotificationPolicy{}, err
	}
	if err := validateChannels(in.CriticalChannels); err != nil {
		return generated.NotificationPolicy{}, err
	}
	if err := validateOptionalWebhookURLs(in); err != nil {
		return generated.NotificationPolicy{}, err
	}
	policy, err := s.store.UpdateNotificationPolicy(ctx, generated.UpdateNotificationPolicyParams{
		ID: id, Name: in.Name, InfoChannels: in.InfoChannels, WarningChannels: in.WarningChannels,
		CriticalChannels: in.CriticalChannels, QuietHoursStart: parseClockTime(in.QuietHoursStart),
		QuietHoursEnd: parseClockTime(in.QuietHoursEnd), QuietHoursTimezone: pgutil.Text(in.QuietHoursTimezone),
		WebhookUrl: pgutil.Text(in.WebhookURL), SlackWebhookUrl: pgutil.Text(in.SlackWebhookURL),
		TeamsWebhookUrl: pgutil.Text(in.TeamsWebhookURL),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.NotificationPolicy{}, ErrNotificationPolicyNotFound
		}
		return generated.NotificationPolicy{}, fmt.Errorf("update notification policy: %w", err)
	}
	return policy, nil
}

func (s *NotificationPolicyService) Delete(ctx context.Context, id uuid.UUID) error {
	policy, err := s.store.GetNotificationPolicyByID(ctx, id)
	if err != nil {
		return ErrNotificationPolicyNotFound
	}
	if policy.IsDefault {
		return errors.New("the default notification policy cannot be deleted")
	}
	if err := s.store.DeleteNotificationPolicy(ctx, id); err != nil {
		return fmt.Errorf("delete notification policy: %w", err)
	}
	return nil
}

// EnsureDefaultPolicy creates the system default policy (INFO: none,
// WARNING/CRITICAL: IN_APP) if one doesn't already exist -- called once
// at startup, mirroring cmd/seed's own idempotent "create if missing"
// pattern, so every alert rule that doesn't reference a specific policy
// still has somewhere to resolve channels from.
func (s *NotificationPolicyService) EnsureDefaultPolicy(ctx context.Context) error {
	if _, err := s.store.GetDefaultNotificationPolicy(ctx); err == nil {
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("check default notification policy: %w", err)
	}
	_, err := s.store.CreateNotificationPolicy(ctx, generated.CreateNotificationPolicyParams{
		Name: "Default", IsDefault: true, InfoChannels: []string{}, WarningChannels: []string{string(ChannelInApp)},
		CriticalChannels: []string{string(ChannelInApp)},
	})
	if err != nil {
		return fmt.Errorf("create default notification policy: %w", err)
	}
	return nil
}

// parseClockTime converts an optional "HH:MM" quiet-hours boundary (spec
// §29) to pgtype.Time -- invalid/unparseable input is treated as "not
// set" rather than rejected, since quiet hours are optional everywhere
// they're used.
func parseClockTime(hhmm *string) pgtype.Time {
	if hhmm == nil || *hhmm == "" {
		return pgtype.Time{}
	}
	t, err := time.Parse("15:04", *hhmm)
	if err != nil {
		return pgtype.Time{}
	}
	microseconds := (int64(t.Hour())*3600 + int64(t.Minute())*60) * 1_000_000
	return pgtype.Time{Microseconds: microseconds, Valid: true}
}
