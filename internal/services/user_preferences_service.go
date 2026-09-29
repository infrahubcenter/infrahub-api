package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/repository"
)

// Theme values -- the single, canonical theme system (Step 21). There is
// no other theme mechanism anywhere in this project to conflict with.
const (
	ThemeSystem = "SYSTEM"
	ThemeLight  = "LIGHT"
	ThemeDark   = "DARK"
)

var validThemes = map[string]bool{ThemeSystem: true, ThemeLight: true, ThemeDark: true}

// Date format values -- deliberately a closed set of display formats, not
// a free-form strftime pattern (nothing here needs that expressiveness,
// and a closed set is trivially safe to render without a template engine).
const (
	DateFormatISO = "YYYY-MM-DD"
	DateFormatUS  = "MM/DD/YYYY"
	DateFormatEU  = "DD/MM/YYYY"
)

var validDateFormats = map[string]bool{DateFormatISO: true, DateFormatUS: true, DateFormatEU: true}

// mutableNotificationCategories is every notifications.category (migration
// 025) a user may mute, i.e. every one except CRITICAL_ALERT -- a critical
// alert must always still reach every admin/authorized member, mirroring
// NotificationService.NotifyAlert's existing "Admins always receive every
// alert" guarantee. Muting is opt-out (an empty/absent list means "muted
// nothing"), never opt-in, so a user who never visits Settings keeps
// receiving everything exactly as before Step 21.
var mutableNotificationCategories = map[string]bool{
	"WARNING": true, "OPERATIONS": true, "DATABASE_EVENT": true, "VM_EVENT": true, "DOCKER_EVENT": true, "SYSTEM_EVENT": true,
}

// UserPreferences is one user's personal settings (Step 21's /settings
// Personal tab) -- display name/email are read from AuthenticatedUser
// instead (see MeSettingsHandler), never duplicated here.
type UserPreferences struct {
	Theme                       string
	Timezone                    string
	DateFormat                  string
	MutedNotificationCategories []string
}

func defaultUserPreferences() UserPreferences {
	return UserPreferences{Theme: ThemeSystem, Timezone: "UTC", DateFormat: DateFormatISO, MutedNotificationCategories: []string{}}
}

// UserPreferencesService is the personal-settings backend. Every method is
// self-service by construction (callers always pass the requesting user's
// own ID -- see MeSettingsHandler, the only caller); there is no
// admin-on-behalf-of-another-user path here, unlike AuthService.UpdateUserAccount.
type UserPreferencesService struct {
	store *repository.Store
}

func NewUserPreferencesService(store *repository.Store) *UserPreferencesService {
	return &UserPreferencesService{store: store}
}

// Get returns userID's preferences, or the documented defaults if they
// have never saved any -- a user who has never opened Settings is not an
// error case.
func (s *UserPreferencesService) Get(ctx context.Context, userID uuid.UUID) (UserPreferences, error) {
	row, err := s.store.Queries.GetUserPreferences(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return defaultUserPreferences(), nil
		}
		return UserPreferences{}, fmt.Errorf("load user preferences: %w", err)
	}
	return UserPreferences{
		Theme: row.Theme, Timezone: row.Timezone, DateFormat: row.DateFormat,
		MutedNotificationCategories: row.MutedNotificationCategories,
	}, nil
}

// UpdateUserPreferencesInput is the requested change -- every field
// optional (nil means "leave unchanged"), mirroring
// AuthService.UpdateUserAccountInput's own shape.
type UpdateUserPreferencesInput struct {
	Theme                       *string
	Timezone                    *string
	DateFormat                  *string
	MutedNotificationCategories *[]string
}

// Update validates and applies in on top of userID's current preferences
// (defaults, if they have none yet), returning the full resulting state.
func (s *UserPreferencesService) Update(ctx context.Context, userID uuid.UUID, in UpdateUserPreferencesInput) (UserPreferences, error) {
	current, err := s.Get(ctx, userID)
	if err != nil {
		return UserPreferences{}, err
	}

	if in.Theme != nil {
		if !validThemes[*in.Theme] {
			return UserPreferences{}, fmt.Errorf("%w: theme must be one of SYSTEM, LIGHT, DARK", ErrValidation)
		}
		current.Theme = *in.Theme
	}
	if in.Timezone != nil {
		tz := strings.TrimSpace(*in.Timezone)
		if tz == "" {
			return UserPreferences{}, fmt.Errorf("%w: timezone is required", ErrValidation)
		}
		if _, err := time.LoadLocation(tz); err != nil {
			return UserPreferences{}, fmt.Errorf("%w: %q is not a recognized timezone", ErrValidation, tz)
		}
		current.Timezone = tz
	}
	if in.DateFormat != nil {
		if !validDateFormats[*in.DateFormat] {
			return UserPreferences{}, fmt.Errorf("%w: date_format must be one of %s, %s, %s", ErrValidation, DateFormatISO, DateFormatUS, DateFormatEU)
		}
		current.DateFormat = *in.DateFormat
	}
	if in.MutedNotificationCategories != nil {
		for _, category := range *in.MutedNotificationCategories {
			if !mutableNotificationCategories[category] {
				return UserPreferences{}, fmt.Errorf("%w: %q cannot be muted", ErrValidation, category)
			}
		}
		current.MutedNotificationCategories = dedupeStrings(*in.MutedNotificationCategories)
	}

	row, err := s.store.Queries.UpsertUserPreferences(ctx, generated.UpsertUserPreferencesParams{
		UserID: userID, Theme: current.Theme, Timezone: current.Timezone, DateFormat: current.DateFormat,
		MutedNotificationCategories: current.MutedNotificationCategories,
	})
	if err != nil {
		return UserPreferences{}, fmt.Errorf("save user preferences: %w", err)
	}
	return UserPreferences{
		Theme: row.Theme, Timezone: row.Timezone, DateFormat: row.DateFormat,
		MutedNotificationCategories: row.MutedNotificationCategories,
	}, nil
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
