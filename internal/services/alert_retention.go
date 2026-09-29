package services

import (
	"context"
	"log/slog"
	"time"

	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// AlertRetentionService deletes terminal (RESOLVED/SUPPRESSED) alerts
// and old notification delivery records past their configured retention
// window (spec §48) -- ACTIVE/ACKNOWLEDGED alerts are never touched
// regardless of age, and audit_logs are a completely separate,
// append-only table this never reads or writes (spec §48: "Do not
// delete audit logs based on alert retention").
type AlertRetentionService struct {
	store                     *repository.Store
	alertRetentionDays        int32
	notificationRetentionDays int32
	logger                    *slog.Logger
}

// NewAlertRetentionService creates an AlertRetentionService.
func NewAlertRetentionService(store *repository.Store, alertRetentionDays, notificationRetentionDays int32, logger *slog.Logger) *AlertRetentionService {
	if logger == nil {
		logger = slog.Default()
	}
	return &AlertRetentionService{store: store, alertRetentionDays: alertRetentionDays, notificationRetentionDays: notificationRetentionDays, logger: logger}
}

// Run ticks once a day, mirroring every other retention service in this
// project (DatabaseRetentionService, DockerRetentionService).
func (s *AlertRetentionService) Run(ctx context.Context) {
	s.cleanup(ctx)
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanup(ctx)
		}
	}
}

func (s *AlertRetentionService) cleanup(ctx context.Context) {
	alertCutoff := time.Now().AddDate(0, 0, -int(s.alertRetentionDays))
	if deleted, err := s.store.DeleteAlertsOlderThan(ctx, pgutil.Timestamptz(alertCutoff)); err != nil {
		s.logger.Error("alert retention: failed to delete old alerts", "error", err)
	} else if deleted > 0 {
		s.logger.Info("alert retention: deleted old terminal alerts", "count", deleted)
	}

	notifCutoff := time.Now().AddDate(0, 0, -int(s.notificationRetentionDays))
	if deleted, err := s.store.DeleteNotificationsOlderThan(ctx, pgutil.Timestamptz(notifCutoff)); err != nil {
		s.logger.Error("alert retention: failed to delete old notifications", "error", err)
	} else if deleted > 0 {
		s.logger.Info("alert retention: deleted old notifications", "count", deleted)
	}
}
