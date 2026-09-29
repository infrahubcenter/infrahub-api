package services

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// NotificationPayload is everything a provider needs to deliver one
// notification -- deliberately a flat struct of display-safe fields.
// Never carries a password, SSH key, database credential, or any other
// secret (spec §25/§55: "no secrets in notifications... no credentials
// in alerts").
type NotificationPayload struct {
	AlertID         uuid.UUID
	Severity        AlertSeverity
	Status          AlertStatus
	ResourceName    string
	ResourceType    string
	AlertType       string
	Title           string
	Body            string
	CurrentValue    *float64
	Threshold       float64
	Timestamp       time.Time
	RecipientUserID *uuid.UUID // nil for a channel with no per-user recipient (WEBHOOK)
	RecipientEmail  string
	WebhookURL      string
	// SlackWebhookURL/TeamsWebhookURL are the policy's own destination for
	// those two channels -- independent of WebhookURL (the generic WEBHOOK
	// channel's target). See SlackProvider/TeamsProvider below.
	SlackWebhookURL string
	TeamsWebhookURL string
}

// NotificationProvider is the extensibility seam spec §26 asks for --
// EmailProvider/SlackProvider/TeamsProvider can each implement this
// without touching NotificationService's routing/dedup/cooldown logic.
// Send's error is never fatal to the underlying alert (spec §53: "If
// email/webhook fails: Alert remains ACTIVE. Notification: FAILED. Do
// not mark the actual infrastructure alert resolved.").
type NotificationProvider interface {
	Channel() NotificationChannel
	Validate(payload NotificationPayload) error
	Send(ctx context.Context, payload NotificationPayload) error
}

// InAppProvider's "delivery" is the notifications row NotificationService
// already writes before calling any provider -- Send is a no-op success,
// there is nothing else to transmit.
type InAppProvider struct{}

func (InAppProvider) Channel() NotificationChannel                    { return ChannelInApp }
func (InAppProvider) Validate(NotificationPayload) error              { return nil }
func (InAppProvider) Send(context.Context, NotificationPayload) error { return nil }

// WebhookProvider posts the exact fields spec §25 lists, as JSON, to the
// policy-configured URL -- never a raw query/command, never a secret.
type WebhookProvider struct {
	client  *http.Client
	timeout time.Duration
}

func NewWebhookProvider(timeout time.Duration) *WebhookProvider {
	return &WebhookProvider{client: &http.Client{Timeout: timeout}, timeout: timeout}
}

func (WebhookProvider) Channel() NotificationChannel { return ChannelWebhook }

func (WebhookProvider) Validate(payload NotificationPayload) error {
	if payload.WebhookURL == "" {
		return fmt.Errorf("webhook notification policy has no configured URL")
	}
	return nil
}

type webhookBody struct {
	AlertID      string   `json:"alert_id"`
	Severity     string   `json:"severity"`
	Resource     string   `json:"resource"`
	ResourceType string   `json:"resource_type"`
	AlertType    string   `json:"alert_type"`
	CurrentValue *float64 `json:"current_value,omitempty"`
	Threshold    float64  `json:"threshold"`
	Status       string   `json:"status"`
	Timestamp    string   `json:"timestamp"`
}

func (p WebhookProvider) Send(ctx context.Context, payload NotificationPayload) error {
	if err := p.Validate(payload); err != nil {
		return err
	}
	body, err := json.Marshal(webhookBody{
		AlertID: payload.AlertID.String(), Severity: string(payload.Severity), Resource: payload.ResourceName,
		ResourceType: payload.ResourceType, AlertType: payload.AlertType, CurrentValue: payload.CurrentValue,
		Threshold: payload.Threshold, Status: string(payload.Status), Timestamp: payload.Timestamp.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("encode webhook payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, payload.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook endpoint returned status %d", resp.StatusCode)
	}
	return nil
}

// alertSummaryLine is the one-line human summary shared by every
// chat-style provider (Slack/Teams) -- the raw fields, not HTML/Markdown,
// since each provider formats it into its own message shape.
func alertSummaryLine(payload NotificationPayload) string {
	return fmt.Sprintf("%s (%s): %s", payload.ResourceName, payload.ResourceType, payload.Body)
}

// severityEmoji/severityColor give Slack/Teams messages an at-a-glance
// severity cue without the recipient having to read the text.
func severityEmoji(s AlertSeverity) string {
	switch s {
	case AlertSeverityCritical:
		return "🔴"
	case AlertSeverityWarning:
		return "🟡"
	default:
		return "🔵"
	}
}

func severityColor(s AlertSeverity) string {
	switch s {
	case AlertSeverityCritical:
		return "D32F2F"
	case AlertSeverityWarning:
		return "F9A825"
	default:
		return "1976D2"
	}
}

// sanitizeHeaderValue strips CR/LF from a value that will be interpolated
// into an SMTP header -- a defensive check, not a trust boundary this
// value is expected to actually cross (Title/Body are backend-generated
// by alert_engine.go, never client-supplied; RecipientEmail comes from
// users.email, validated at account-creation time), but header injection
// is cheap to categorically rule out here regardless.
func sanitizeHeaderValue(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// EmailProvider sends one plain-text email per notification over SMTP
// (stdlib net/smtp -- no external mail library needed for this). Empty
// Host means email delivery is unconfigured (see config.SMTPHost's doc
// comment): Validate fails clearly rather than Send attempting a doomed
// connection to an empty address.
type EmailProvider struct {
	host     string
	port     int32
	username string
	password string
	from     string
	useTLS   bool
	timeout  time.Duration
}

func NewEmailProvider(host string, port int32, username, password, from string, useTLS bool, timeout time.Duration) *EmailProvider {
	return &EmailProvider{host: host, port: port, username: username, password: password, from: from, useTLS: useTLS, timeout: timeout}
}

func (EmailProvider) Channel() NotificationChannel { return ChannelEmail }

func (p *EmailProvider) Validate(payload NotificationPayload) error {
	if p.host == "" {
		return fmt.Errorf("email delivery is not configured (SMTP_HOST is unset)")
	}
	if payload.RecipientEmail == "" {
		return fmt.Errorf("email notification has no recipient address")
	}
	return nil
}

func (p *EmailProvider) Send(ctx context.Context, payload NotificationPayload) error {
	if err := p.Validate(payload); err != nil {
		return err
	}
	subject := fmt.Sprintf("[InfraHub][%s] %s", payload.Severity, payload.Title)
	return sendSMTPMail(ctx, smtpSettings{
		host: p.host, port: p.port, username: p.username, password: p.password, from: p.from,
		useTLS: p.useTLS, timeout: p.timeout,
	}, payload.RecipientEmail, subject, alertSummaryLine(payload))
}

// smtpSettings is the shared low-level SMTP configuration sendSMTPMail
// needs -- EmailProvider (alert notifications) and InviteMailer (user
// invites) each hold their own copy of these same five config.SMTP*
// values, but there is exactly one real SMTP-sending implementation
// between them.
type smtpSettings struct {
	host, username, password, from string
	port                           int32
	useTLS                         bool
	timeout                        time.Duration
}

// sendSMTPMail builds one plain-text RFC 822 message and sends it over
// SMTP (stdlib net/smtp -- no external mail library needed), racing the
// blocking call against ctx/settings.timeout since net/smtp has no
// context support (the goroutine itself may still be running when we
// give up on it; an acceptable leak for a rare timeout case, same
// tradeoff every context-wrapped blocking stdlib call in Go makes).
func sendSMTPMail(ctx context.Context, settings smtpSettings, toEmail, subject, body string) error {
	if settings.host == "" {
		return fmt.Errorf("email delivery is not configured (SMTP_HOST is unset)")
	}
	if toEmail == "" {
		return fmt.Errorf("email has no recipient address")
	}
	subject = sanitizeHeaderValue(subject)
	to := sanitizeHeaderValue(toEmail)
	from := sanitizeHeaderValue(settings.from)
	msg := buildPlainTextEmail(from, to, subject, body)

	addr := fmt.Sprintf("%s:%d", settings.host, settings.port)
	var auth smtp.Auth
	if settings.username != "" {
		auth = smtp.PlainAuth("", settings.username, settings.password, settings.host)
	}

	done := make(chan error, 1)
	go func() {
		// Routed by PORT, not settings.useTLS -- the two real TLS modes an
		// SMTP provider offers are implicit TLS (SMTPS, always port 465:
		// the client must speak TLS from the very first byte) and STARTTLS
		// (port 587/25: connect in plaintext, then upgrade mid-session --
		// which is exactly what stdlib's smtp.SendMail already does
		// automatically whenever the server advertises the STARTTLS
		// extension). Gmail, Outlook, SendGrid, etc. all use 587+STARTTLS
		// as their standard port; dialing that with an immediate TLS
		// handshake (what useTLS==true used to trigger unconditionally)
		// fails outright, since the server is still expecting a plaintext
		// EHLO first. useTLS itself no longer decides the mode -- it was
		// never able to express "which of the two" in the first place.
		if settings.port == 465 {
			done <- sendSMTPImplicitTLS(addr, settings.host, from, auth, to, msg)
		} else {
			done <- smtp.SendMail(addr, auth, from, []string{to}, msg)
		}
	}()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("send email: %w", err)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(settings.timeout):
		return fmt.Errorf("send email: timed out after %s", settings.timeout)
	}
}

// sendSMTPImplicitTLS handles SMTPS (typically port 465) -- smtp.SendMail
// only ever does plaintext-or-opportunistic-STARTTLS, never implicit
// TLS, so sending via a provider configured for it needs its own dial.
func sendSMTPImplicitTLS(addr, host, from string, auth smtp.Auth, to string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("smtp handshake: %w", err)
	}
	defer client.Close()
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("write email body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close email body: %w", err)
	}
	return client.Quit()
}

// InviteMailer sends the "you've been invited" email when a new user is
// created with a temporary password -- reuses sendSMTPMail, the exact
// same SMTP mechanics EmailProvider uses for alert notifications, just a
// different message with no NotificationPayload/policy/channel concept
// involved (invites are unconditional, not a selectable per-severity
// channel).
type InviteMailer struct {
	settings   smtpSettings
	appBaseURL string
}

// NewInviteMailer creates an InviteMailer. host may be empty (SMTP not
// configured) -- callers check Configured() before deciding whether
// calling SendInvite is worth attempting.
func NewInviteMailer(host string, port int32, username, password, from string, useTLS bool, timeout time.Duration, appBaseURL string) *InviteMailer {
	return &InviteMailer{
		settings:   smtpSettings{host: host, port: port, username: username, password: password, from: from, useTLS: useTLS, timeout: timeout},
		appBaseURL: appBaseURL,
	}
}

// Configured reports whether SMTP_HOST is set. Callers use this to
// decide whether to bother calling SendInvite at all, and to word their
// own log/audit messages accordingly, rather than treating "SMTP isn't
// configured yet" as a send failure. Nil-safe: a caller (e.g. a test
// harness) that never wired an InviteMailer at all gets "not configured"
// rather than a nil-pointer panic.
func (m *InviteMailer) Configured() bool {
	return m != nil && m.settings.host != ""
}

// SendInvite emails toEmail the account's temporary password and a link
// to sign in. Never the only way an admin learns the password -- the
// create-user API response still returns it too (see users.go), so a
// missing/misconfigured SMTP setup never locks an admin out of inviting
// people, it just means they relay the password shown on-screen instead.
func (m *InviteMailer) SendInvite(ctx context.Context, toEmail, name, temporaryPassword string) error {
	subject := "You've been invited to InfraHub"
	body := fmt.Sprintf(
		"Hi %s,\n\nAn InfraHub account has been created for you.\n\nEmail: %s\nTemporary password: %s\n\nSign in and change your password here: %s\n",
		name, toEmail, temporaryPassword, m.appBaseURL,
	)
	return sendSMTPMail(ctx, m.settings, toEmail, subject, body)
}

func buildPlainTextEmail(from, to, subject, body string) []byte {
	var buf bytes.Buffer
	buf.WriteString("From: " + from + "\r\n")
	buf.WriteString("To: " + to + "\r\n")
	buf.WriteString("Subject: " + subject + "\r\n")
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
	buf.WriteString("\r\n")
	buf.WriteString(body)
	buf.WriteString("\r\n")
	return buf.Bytes()
}

// SlackProvider posts to a Slack "Incoming Webhook" URL -- the standard,
// no-app-approval-needed way to deliver a message into a Slack channel
// (https://api.slack.com/messaging/webhooks). The payload shape Slack
// expects is just {"text": "..."}; Slack's own mrkdwn syntax (*bold*)
// renders in-channel.
type SlackProvider struct {
	client *http.Client
}

func NewSlackProvider(timeout time.Duration) *SlackProvider {
	return &SlackProvider{client: &http.Client{Timeout: timeout}}
}

func (SlackProvider) Channel() NotificationChannel { return ChannelSlack }

func (SlackProvider) Validate(payload NotificationPayload) error {
	if payload.SlackWebhookURL == "" {
		return fmt.Errorf("slack notification policy has no configured webhook URL")
	}
	return nil
}

func (p *SlackProvider) Send(ctx context.Context, payload NotificationPayload) error {
	if err := p.Validate(payload); err != nil {
		return err
	}
	text := fmt.Sprintf("%s *[%s] %s*\n%s", severityEmoji(payload.Severity), payload.Severity, payload.Title, alertSummaryLine(payload))
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return fmt.Errorf("encode slack payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, payload.SlackWebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// TeamsProvider posts to a Microsoft Teams "Incoming Webhook" connector
// URL, using the classic MessageCard format Teams connectors accept
// (https://learn.microsoft.com/en-us/outlook/actionable-messages/message-card-reference).
type TeamsProvider struct {
	client *http.Client
}

func NewTeamsProvider(timeout time.Duration) *TeamsProvider {
	return &TeamsProvider{client: &http.Client{Timeout: timeout}}
}

func (TeamsProvider) Channel() NotificationChannel { return ChannelTeams }

func (TeamsProvider) Validate(payload NotificationPayload) error {
	if payload.TeamsWebhookURL == "" {
		return fmt.Errorf("teams notification policy has no configured webhook URL")
	}
	return nil
}

type teamsMessageCard struct {
	Type       string `json:"@type"`
	Context    string `json:"@context"`
	Summary    string `json:"summary"`
	ThemeColor string `json:"themeColor,omitempty"`
	Title      string `json:"title"`
	Text       string `json:"text"`
}

func (p *TeamsProvider) Send(ctx context.Context, payload NotificationPayload) error {
	if err := p.Validate(payload); err != nil {
		return err
	}
	card := teamsMessageCard{
		Type: "MessageCard", Context: "http://schema.org/extensions", Summary: payload.Title,
		ThemeColor: severityColor(payload.Severity), Title: fmt.Sprintf("[%s] %s", payload.Severity, payload.Title),
		Text: alertSummaryLine(payload),
	}
	body, err := json.Marshal(card)
	if err != nil {
		return fmt.Errorf("encode teams payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, payload.TeamsWebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build teams request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("teams request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("teams webhook returned status %d", resp.StatusCode)
	}
	return nil
}
