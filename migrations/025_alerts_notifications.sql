-- +goose Up

-- Step 16: central infrastructure alerts + notifications, layered on top
-- of Steps 6/8/13's existing metrics (monitoring_snapshots,
-- docker_container_metric_snapshots, standalone_database_metrics/
-- standalone_database_deep_metrics) and Step 7's recommendations. Alerts
-- are deliberately a SEPARATE concept from recommendations (spec §41):
-- a recommendation is an advisory, upserted once per collection cycle
-- with no duration/hysteresis; an alert is a stateful, deduplicated,
-- threshold+duration+recovery-gated lifecycle that drives notifications.
-- Nothing here executes any remediation -- see database_operations
-- (Step 14) for the only operation-execution path in this project.

-- notification_policies: which channels fire per severity, resolved by
-- an alert_rule (falling back to a single system default when a rule
-- doesn't reference one). Channel values beyond IN_APP/WEBHOOK are valid
-- but currently unimplemented (spec §23/§26: "implement additional
-- channels only if infrastructure already exists" -- there is no email
-- infrastructure in this project yet) -- selecting them just means no
-- provider is registered for that channel, not a schema-level rejection,
-- so a future EmailProvider/SlackProvider/TeamsProvider needs no
-- migration to plug in.
CREATE TABLE notification_policies (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                 text NOT NULL,
    is_default           boolean NOT NULL DEFAULT false,
    info_channels        text[] NOT NULL DEFAULT '{}',
    warning_channels     text[] NOT NULL DEFAULT '{IN_APP}',
    critical_channels    text[] NOT NULL DEFAULT '{IN_APP}',
    -- Quiet hours (spec §29): "Warnings may be delayed. Critical alerts
    -- may still notify immediately." -- enforced by the notification
    -- service, never by silently dropping a critical notification.
    quiet_hours_start    time,
    quiet_hours_end      time,
    quiet_hours_timezone text,
    webhook_url          text,
    created_by           uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX notification_policies_single_default_idx ON notification_policies(is_default) WHERE is_default;

CREATE TRIGGER notification_policies_set_updated_at
    BEFORE UPDATE ON notification_policies
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- alert_rules: Admin-configured thresholds (spec §8). One rule per
-- (resource[, container], alert_type) -- re-saving a rule updates it in
-- place rather than creating a second, conflicting rule for the same
-- condition. container_id is set only for DOCKER_CONTAINER-scoped rules
-- (a container is never its own `resources` row -- spec's existing
-- architecture -- so resource_id always points at the *VM's* resource,
-- for authorization, and container_id narrows it to one container).
-- breach_started_at is the engine's own duration-tracking state (spec
-- §9: "do not trigger from a single bad sample") -- reset to NULL
-- whenever the condition stops being true before duration_seconds
-- elapses, so a flapping metric never silently accumulates toward
-- triggering.
CREATE TABLE alert_rules (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id             uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    container_id            uuid REFERENCES docker_containers(id) ON DELETE CASCADE,
    alert_type              text NOT NULL CHECK (alert_type IN (
        'VM_HIGH_CPU', 'VM_HIGH_MEMORY', 'VM_HIGH_STORAGE', 'VM_UNAVAILABLE',
        'DOCKER_CONTAINER_STOPPED', 'DOCKER_CONTAINER_RESTARTING', 'DOCKER_CONTAINER_UNHEALTHY', 'DOCKER_CONTAINER_OOM',
        'DATABASE_UNAVAILABLE', 'DATABASE_HIGH_CONNECTIONS', 'DATABASE_HIGH_LATENCY', 'DATABASE_LOCK_CONTENTION',
        'DATABASE_REPLICATION_LAG', 'DATABASE_HIGH_STORAGE', 'DATABASE_LOW_CACHE_HIT'
    )),
    -- DB_STORAGE_BYTES (not "...PERCENT"): a standalone/managed database
    -- has no tracked capacity to compute a percentage against (unlike a
    -- VM's total_storage_bytes) -- the honest evaluable signal is the
    -- database's own reported size in bytes, compared against an
    -- Admin-chosen absolute threshold.
    metric                  text NOT NULL CHECK (metric IN (
        'CPU_PERCENT', 'MEMORY_PERCENT', 'STORAGE_PERCENT', 'VM_UNREACHABLE',
        'CONTAINER_STOPPED', 'CONTAINER_RESTARTING', 'CONTAINER_UNHEALTHY', 'CONTAINER_RESTART_COUNT',
        'DB_UNREACHABLE', 'DB_CONNECTION_PERCENT', 'DB_LATENCY_P95_MS', 'DB_LOCKS_BLOCKED',
        'DB_REPLICATION_LAG_SECONDS', 'DB_STORAGE_BYTES', 'DB_CACHE_HIT_PERCENT'
    )),
    condition               text NOT NULL CHECK (condition IN ('>', '<', '>=', '<=', '==')),
    threshold               double precision NOT NULL,
    -- NULL means no hysteresis gap: the alert resolves as soon as the
    -- trigger condition itself stops being true (spec §10 still applies
    -- since RESOLVED still only happens via the recovery check, just
    -- with recovery_threshold defaulting to threshold).
    recovery_threshold      double precision,
    duration_seconds        integer NOT NULL DEFAULT 0 CHECK (duration_seconds >= 0),
    severity                text NOT NULL CHECK (severity IN ('INFO', 'WARNING', 'CRITICAL')),
    notification_policy_id  uuid REFERENCES notification_policies(id) ON DELETE SET NULL,
    enabled                 boolean NOT NULL DEFAULT true,
    breach_started_at       timestamptz,
    -- Admin suppression (spec §30) -- distinct from an alert's own
    -- SUPPRESSED status: suppressing the *rule* means no new alert is
    -- created and any currently-active alert for it is marked SUPPRESSED
    -- for the duration, always audited with who/reason/when.
    suppressed_until        timestamptz,
    suppressed_reason       text,
    suppressed_by           uuid REFERENCES users(id) ON DELETE SET NULL,
    created_by              uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT alert_rules_resource_container_type_unique UNIQUE (resource_id, container_id, alert_type)
);

CREATE INDEX alert_rules_resource_idx ON alert_rules(resource_id);
CREATE INDEX alert_rules_enabled_idx ON alert_rules(enabled) WHERE enabled;

CREATE TRIGGER alert_rules_set_updated_at
    BEFORE UPDATE ON alert_rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- alerts: the actual firing lifecycle (spec §3/§12). project_id/group_id
-- are denormalized from the owning resource at creation time purely for
-- the two required indexes below (spec §50) and for Member-scoped
-- dashboard queries that need to filter by project/group without an
-- extra join on every request -- resource_id via resources remains the
-- authoritative authorization check, these are never trusted alone.
CREATE TABLE alerts (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_rule_id      uuid NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    resource_id        uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    container_id       uuid REFERENCES docker_containers(id) ON DELETE CASCADE,
    project_id         uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    group_id           uuid REFERENCES groups(id) ON DELETE SET NULL,
    alert_type         text NOT NULL,
    severity           text NOT NULL CHECK (severity IN ('INFO', 'WARNING', 'CRITICAL')),
    status             text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'ACKNOWLEDGED', 'RESOLVED', 'SUPPRESSED')),
    metric             text NOT NULL,
    current_value      double precision,
    threshold          double precision NOT NULL,
    title              text NOT NULL,
    description        text,
    first_seen_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at       timestamptz NOT NULL DEFAULT now(),
    last_notified_at   timestamptz,
    acknowledged_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_at    timestamptz,
    resolved_at        timestamptz,
    suppressed_at      timestamptz,
    suppressed_reason  text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

-- Deduplication (spec §11): at most one ACTIVE/ACKNOWLEDGED alert per
-- rule at a time -- the engine already checks this before creating one,
-- this is the hard database-level guarantee behind that check.
CREATE UNIQUE INDEX alerts_rule_active_unique ON alerts(alert_rule_id) WHERE status IN ('ACTIVE', 'ACKNOWLEDGED');
CREATE INDEX alerts_status_created_idx ON alerts(status, created_at);
CREATE INDEX alerts_resource_status_idx ON alerts(resource_id, status);
CREATE INDEX alerts_project_status_idx ON alerts(project_id, status);
CREATE INDEX alerts_group_status_idx ON alerts(group_id, status);

CREATE TRIGGER alerts_set_updated_at
    BEFORE UPDATE ON alerts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- alert_events: the timeline (spec §14/§17/§47) -- one row per state
-- transition (CREATED/ESCALATED/DEESCALATED/ACKNOWLEDGED/RESOLVED/
-- SUPPRESSED/UNSUPPRESSED) plus a bounded, coarse SAMPLE row per
-- evaluation cycle while ACTIVE/ACKNOWLEDGED (never per raw metric
-- sample -- the evaluation cycle itself is already much coarser than
-- collection, spec §32 "do not audit every metric sample" applies
-- equally here).
CREATE TABLE alert_events (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id    uuid NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_type  text NOT NULL CHECK (event_type IN (
        'CREATED', 'ESCALATED', 'DEESCALATED', 'ACKNOWLEDGED', 'RESOLVED', 'SUPPRESSED', 'UNSUPPRESSED', 'SAMPLE'
    )),
    status      text NOT NULL,
    value       double precision,
    threshold   double precision,
    message     text,
    actor_id    uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX alert_events_alert_created_idx ON alert_events(alert_id, created_at);

-- notifications: one row per (alert, channel, recipient) delivery
-- attempt -- the dedup/cooldown key spec §44/§45 describes. user_id is
-- NULL for a channel with no per-user recipient concept (WEBHOOK);
-- IN_APP always has one.
CREATE TABLE notifications (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id      uuid REFERENCES alerts(id) ON DELETE CASCADE,
    user_id       uuid REFERENCES users(id) ON DELETE CASCADE,
    category      text NOT NULL CHECK (category IN (
        'CRITICAL_ALERT', 'WARNING', 'OPERATIONS', 'DATABASE_EVENT', 'VM_EVENT', 'DOCKER_EVENT', 'SYSTEM_EVENT'
    )),
    channel       text NOT NULL CHECK (channel IN ('IN_APP', 'EMAIL', 'SLACK', 'TEAMS', 'WEBHOOK')),
    severity      text CHECK (severity IS NULL OR severity IN ('INFO', 'WARNING', 'CRITICAL')),
    title         text NOT NULL,
    body          text,
    status        text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SENT', 'FAILED')),
    error_message text,
    attempt_count integer NOT NULL DEFAULT 0,
    read_at       timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX notifications_user_created_idx ON notifications(user_id, created_at DESC);
CREATE INDEX notifications_alert_channel_idx ON notifications(alert_id, channel);
CREATE INDEX notifications_user_unread_idx ON notifications(user_id) WHERE read_at IS NULL;

-- +goose Down
DROP TABLE notifications;
DROP TABLE alert_events;
DROP TABLE alerts;
DROP TABLE alert_rules;
DROP TABLE notification_policies;
