// Package services: platform_settings.go is the Owner-editable, UI-
// configurable sign-in-method settings store (GitHub OAuth, Google OAuth,
// SMTP for invite emails) -- see migration 047_platform_settings.sql for
// the full design rationale. Read fresh from Postgres on every Get() call,
// exactly like NotificationPolicyService's own "admin edits it via UI, no
// restart needed" precedent -- no cache, no config-struct mutation, no
// service-reconstruction dance. Secrets are encrypted via the same shared
// EncryptionService every other encrypted-at-rest credential in this app
// already uses.
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

// PlatformSettings is the live, resolved view of sign-in-method
// configuration -- a DB-stored value if an Owner has set one, otherwise
// the equivalent .env value, field by field, so an already-deployed
// env-only setup keeps working unchanged until explicitly overridden
// through the UI.
type PlatformSettings struct {
	GitHubClientID     string
	GitHubClientSecret string
	GitHubConfigured   bool
	GoogleClientID     string
	GoogleClientSecret string
	GoogleConfigured   bool
	SMTPHost           string
	SMTPPort           int32
	SMTPUsername       string
	SMTPPassword       string
	SMTPFromEmail      string
	SMTPUseTLS         bool
	SMTPConfigured     bool
}

// PlatformSettingsEnvDefaults is the .env-sourced fallback for any field
// an Owner hasn't overridden via the UI yet -- config.Config's own values,
// captured once at construction (env vars themselves are still
// process-startup-only; only the DB layer on top of them is
// runtime-mutable).
type PlatformSettingsEnvDefaults struct {
	GitHubClientID     string
	GitHubClientSecret string
	GoogleClientID     string
	GoogleClientSecret string
	SMTPHost           string
	SMTPPort           int32
	SMTPUsername       string
	SMTPPassword       string
	SMTPFromEmail      string
	SMTPUseTLS         bool
}

type PlatformSettingsService struct {
	store       *repository.Store
	encryption  *EncryptionService
	envDefaults PlatformSettingsEnvDefaults
}

// NewPlatformSettingsService creates a PlatformSettingsService.
func NewPlatformSettingsService(store *repository.Store, encryption *EncryptionService, envDefaults PlatformSettingsEnvDefaults) *PlatformSettingsService {
	return &PlatformSettingsService{store: store, encryption: encryption, envDefaults: envDefaults}
}

// EnsureRow creates the one settings row if it doesn't already exist --
// called once at startup, mirroring NotificationPolicyService.
// EnsureDefaultPolicy's identical "create if missing" idiom.
func (s *PlatformSettingsService) EnsureRow(ctx context.Context) error {
	if _, err := s.store.GetPlatformSettings(ctx); err == nil {
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("check platform settings: %w", err)
	}
	if _, err := s.store.CreatePlatformSettingsRow(ctx); err != nil {
		return fmt.Errorf("create platform settings row: %w", err)
	}
	return nil
}

// row fetches the one settings row -- every exported method shares this
// identical "there should always be exactly one, created by EnsureRow at
// startup" assumption.
func (s *PlatformSettingsService) row(ctx context.Context) (generated.PlatformSetting, error) {
	row, err := s.store.GetPlatformSettings(ctx)
	if err != nil {
		return generated.PlatformSetting{}, fmt.Errorf("load platform settings: %w", err)
	}
	return row, nil
}

// Get resolves the live, current sign-in-method configuration -- read
// fresh from Postgres on every call, decrypting a secret only when a
// DB-stored one actually exists, otherwise falling back to envDefaults
// field by field.
func (s *PlatformSettingsService) Get(ctx context.Context) (PlatformSettings, error) {
	row, err := s.row(ctx)
	if err != nil {
		return PlatformSettings{}, err
	}

	out := PlatformSettings{
		GitHubClientID: pgutil.TextOrEmpty(row.GithubClientID),
		GoogleClientID: pgutil.TextOrEmpty(row.GoogleClientID),
		SMTPHost:       pgutil.TextOrEmpty(row.SmtpHost),
		SMTPUsername:   pgutil.TextOrEmpty(row.SmtpUsername),
		SMTPFromEmail:  pgutil.TextOrEmpty(row.SmtpFromEmail),
	}
	if out.GitHubClientID == "" {
		out.GitHubClientID = s.envDefaults.GitHubClientID
	}
	if out.GoogleClientID == "" {
		out.GoogleClientID = s.envDefaults.GoogleClientID
	}
	if out.SMTPHost == "" {
		out.SMTPHost = s.envDefaults.SMTPHost
	}
	if out.SMTPUsername == "" {
		out.SMTPUsername = s.envDefaults.SMTPUsername
	}

	if len(row.GithubClientSecretEnc) > 0 {
		secret, err := s.encryption.Decrypt(string(row.GithubClientSecretEnc))
		if err != nil {
			return PlatformSettings{}, fmt.Errorf("decrypt github client secret: %w", err)
		}
		out.GitHubClientSecret = string(secret)
	} else {
		out.GitHubClientSecret = s.envDefaults.GitHubClientSecret
	}
	if len(row.GoogleClientSecretEnc) > 0 {
		secret, err := s.encryption.Decrypt(string(row.GoogleClientSecretEnc))
		if err != nil {
			return PlatformSettings{}, fmt.Errorf("decrypt google client secret: %w", err)
		}
		out.GoogleClientSecret = string(secret)
	} else {
		out.GoogleClientSecret = s.envDefaults.GoogleClientSecret
	}
	if len(row.SmtpPasswordEnc) > 0 {
		secret, err := s.encryption.Decrypt(string(row.SmtpPasswordEnc))
		if err != nil {
			return PlatformSettings{}, fmt.Errorf("decrypt smtp password: %w", err)
		}
		out.SMTPPassword = string(secret)
	} else {
		out.SMTPPassword = s.envDefaults.SMTPPassword
	}

	if row.SmtpPort.Valid {
		out.SMTPPort = row.SmtpPort.Int32
	} else {
		out.SMTPPort = s.envDefaults.SMTPPort
	}
	if row.SmtpUseTls.Valid {
		out.SMTPUseTLS = row.SmtpUseTls.Bool
	} else {
		out.SMTPUseTLS = s.envDefaults.SMTPUseTLS
	}

	out.GitHubConfigured = out.GitHubClientID != "" && out.GitHubClientSecret != ""
	out.GoogleConfigured = out.GoogleClientID != "" && out.GoogleClientSecret != ""
	out.SMTPConfigured = out.SMTPHost != ""
	return out, nil
}

// UpdateGitHub saves the GitHub OAuth Client ID/Secret. clientSecret nil
// (or empty) means "leave the currently stored secret unchanged" -- the
// established masked-credential-edit convention already used elsewhere in
// this app (re-saving just the Client ID never blows away an
// already-configured secret).
func (s *PlatformSettingsService) UpdateGitHub(ctx context.Context, actorID uuid.UUID, clientID string, clientSecret *string) error {
	row, err := s.row(ctx)
	if err != nil {
		return err
	}
	encSecret, err := s.encryptOptional(clientSecret)
	if err != nil {
		return fmt.Errorf("encrypt github client secret: %w", err)
	}
	if _, err := s.store.UpdatePlatformSettingsGitHub(ctx, generated.UpdatePlatformSettingsGitHubParams{
		ID: row.ID, ClientID: pgutil.Text(clientID), ClientSecretEnc: encSecret, UpdatedBy: pgutil.NullUUID(&actorID),
	}); err != nil {
		return fmt.Errorf("update github settings: %w", err)
	}
	return nil
}

// UpdateGoogle mirrors UpdateGitHub exactly, for Google OAuth.
func (s *PlatformSettingsService) UpdateGoogle(ctx context.Context, actorID uuid.UUID, clientID string, clientSecret *string) error {
	row, err := s.row(ctx)
	if err != nil {
		return err
	}
	encSecret, err := s.encryptOptional(clientSecret)
	if err != nil {
		return fmt.Errorf("encrypt google client secret: %w", err)
	}
	if _, err := s.store.UpdatePlatformSettingsGoogle(ctx, generated.UpdatePlatformSettingsGoogleParams{
		ID: row.ID, ClientID: pgutil.Text(clientID), ClientSecretEnc: encSecret, UpdatedBy: pgutil.NullUUID(&actorID),
	}); err != nil {
		return fmt.Errorf("update google settings: %w", err)
	}
	return nil
}

// SMTPUpdateInput is UpdateSMTP's request shape -- Password nil/empty
// means "leave the currently stored password unchanged", same convention
// as UpdateGitHub/UpdateGoogle's client secret.
type SMTPUpdateInput struct {
	Host      string
	Port      int32
	Username  string
	Password  *string
	FromEmail string
	UseTLS    bool
}

// UpdateSMTP saves SMTP/invite-email settings.
func (s *PlatformSettingsService) UpdateSMTP(ctx context.Context, actorID uuid.UUID, in SMTPUpdateInput) error {
	row, err := s.row(ctx)
	if err != nil {
		return err
	}
	encPassword, err := s.encryptOptional(in.Password)
	if err != nil {
		return fmt.Errorf("encrypt smtp password: %w", err)
	}
	if _, err := s.store.UpdatePlatformSettingsSMTP(ctx, generated.UpdatePlatformSettingsSMTPParams{
		ID: row.ID, Host: pgutil.Text(in.Host), Port: pgutil.Int4(in.Port), Username: pgutil.Text(in.Username),
		PasswordEnc: encPassword, FromEmail: pgutil.Text(in.FromEmail), UseTls: pgutil.Bool(in.UseTLS),
		UpdatedBy: pgutil.NullUUID(&actorID),
	}); err != nil {
		return fmt.Errorf("update smtp settings: %w", err)
	}
	return nil
}

// encryptOptional encrypts secret if it's non-nil and non-empty, else
// returns nil (meaning "leave whatever's already stored unchanged" to
// every UpdatePlatformSettings* query's COALESCE).
func (s *PlatformSettingsService) encryptOptional(secret *string) ([]byte, error) {
	if secret == nil || *secret == "" {
		return nil, nil
	}
	enc, err := s.encryption.Encrypt([]byte(*secret))
	if err != nil {
		return nil, err
	}
	return []byte(enc), nil
}

// smtpTestTimeout bounds both TestSMTP's real send attempt and the OAuth
// credential-recognition probes below -- generous enough for a real SMTP
// round trip, short enough that a hung Test Connection button isn't a
// realistic complaint.
const smtpTestTimeout = 10 * time.Second
