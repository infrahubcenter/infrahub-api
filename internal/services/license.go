package services

// Subscription plans and license keys. Every installation runs the free
// Community plan unless INFRAHUB_LICENSE_KEY holds a valid key for a paid
// plan. Keys are signed by Infra Hub Center (Ed25519) and verified here
// against the public key below, so a plan can't be unlocked by editing
// configuration -- only by a key issued for it.
//
// The same tiers are published on the marketing site
// (infrahub-site/src/lib/product.ts) and shown on the console's Plans &
// Billing page (infrahub-ui/src/lib/plans.ts) -- keep all three in sync.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// licensePublicKey verifies license signatures. The matching private key
// never leaves Infra Hub Center.
const licensePublicKey = "KfyjXYSoAqptj8ae3nC+9EfcrYYM7BYJrsQ7hq9xcu4="

const licensePrefix = "IHC1."

// LimitKind is one countable thing a plan limits.
type LimitKind string

const (
	LimitVMs           LimitKind = "vms"
	LimitDatabases     LimitKind = "databases"
	LimitObjectStorage LimitKind = "object_storage"
	LimitDockerHosts   LimitKind = "docker_hosts"
	LimitK8sClusters   LimitKind = "k8s_clusters"
	LimitUsers         LimitKind = "users"
)

var limitLabels = map[LimitKind][2]string{
	LimitVMs:           {"VM", "VMs"},
	LimitDatabases:     {"database", "databases"},
	LimitObjectStorage: {"object storage bucket", "object storage buckets"},
	LimitDockerHosts:   {"Docker host", "Docker hosts"},
	LimitK8sClusters:   {"Kubernetes cluster", "Kubernetes clusters"},
	LimitUsers:         {"user", "users"},
}

// AllLimitKinds is the display order.
var AllLimitKinds = []LimitKind{LimitVMs, LimitDatabases, LimitObjectStorage, LimitDockerHosts, LimitK8sClusters, LimitUsers}

// Unlimited marks a limit or retention with no cap.
const Unlimited = -1

type Plan struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	Limits               map[LimitKind]int `json:"limits"`
	MetricsRetentionDays int               `json:"metrics_retention_days"`
	LogRetentionDays     int               `json:"log_retention_days"`
}

var Plans = map[string]Plan{
	"community": {ID: "community", Name: "Community", MetricsRetentionDays: 3, LogRetentionDays: 3, Limits: map[LimitKind]int{
		LimitVMs: 2, LimitDatabases: 1, LimitObjectStorage: 1, LimitDockerHosts: 1, LimitK8sClusters: 1, LimitUsers: 1,
	}},
	"team": {ID: "team", Name: "Team", MetricsRetentionDays: 30, LogRetentionDays: 14, Limits: map[LimitKind]int{
		LimitVMs: 25, LimitDatabases: 10, LimitObjectStorage: 5, LimitDockerHosts: 10, LimitK8sClusters: 3, LimitUsers: 15,
	}},
	"business": {ID: "business", Name: "Business", MetricsRetentionDays: 90, LogRetentionDays: 30, Limits: map[LimitKind]int{
		LimitVMs: 100, LimitDatabases: 50, LimitObjectStorage: 25, LimitDockerHosts: 50, LimitK8sClusters: 15, LimitUsers: Unlimited,
	}},
	"enterprise": {ID: "enterprise", Name: "Enterprise", MetricsRetentionDays: Unlimited, LogRetentionDays: Unlimited, Limits: map[LimitKind]int{
		LimitVMs: Unlimited, LimitDatabases: Unlimited, LimitObjectStorage: Unlimited, LimitDockerHosts: Unlimited, LimitK8sClusters: Unlimited, LimitUsers: Unlimited,
	}},
}

// License is the plan this installation is entitled to, and why.
type License struct {
	Plan      Plan       `json:"plan"`
	Licensee  string     `json:"licensee,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Status: "community" (no key), "active", "expired" or "invalid" --
	// the last two fall back to Community limits.
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type licensePayload struct {
	Plan     string `json:"plan"`
	Licensee string `json:"licensee"`
	Expires  string `json:"expires"` // YYYY-MM-DD, empty = perpetual
}

// ParseLicense verifies key and returns the entitled plan. An empty key is
// the free Community plan; a bad or expired key also falls back to it.
func ParseLicense(key string, now time.Time) License {
	community := License{Plan: Plans["community"], Status: "community"}
	key = strings.TrimSpace(key)
	if key == "" {
		return community
	}
	fail := func(status, msg string) License {
		community.Status, community.Error = status, msg
		return community
	}
	if !strings.HasPrefix(key, licensePrefix) {
		return fail("invalid", "license key format not recognised")
	}
	parts := strings.Split(strings.TrimPrefix(key, licensePrefix), ".")
	if len(parts) != 2 {
		return fail("invalid", "license key format not recognised")
	}
	pub, _ := base64.StdEncoding.DecodeString(licensePublicKey)
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), []byte(licensePrefix+parts[0]), sig) {
		return fail("invalid", "license key signature is not valid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fail("invalid", "license key payload is not valid")
	}
	var p licensePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return fail("invalid", "license key payload is not valid")
	}
	plan, ok := Plans[p.Plan]
	if !ok {
		return fail("invalid", fmt.Sprintf("unknown plan %q", p.Plan))
	}
	lic := License{Plan: plan, Licensee: p.Licensee, Status: "active"}
	if p.Expires != "" {
		exp, err := time.Parse("2006-01-02", p.Expires)
		if err != nil {
			return fail("invalid", "license key expiry is not valid")
		}
		end := exp.Add(24*time.Hour - time.Second)
		lic.ExpiresAt = &end
		if now.After(end) {
			out := fail("expired", "license expired on "+p.Expires)
			out.Licensee, out.ExpiresAt = p.Licensee, &end
			return out
		}
	}
	return lic
}

// CapRetention returns days limited to the plan's cap (for the retention
// settings read from configuration).
func (p Plan) CapRetention(days int32, logs bool) int32 {
	limit := p.MetricsRetentionDays
	if logs {
		limit = p.LogRetentionDays
	}
	if limit == Unlimited || (days > 0 && days <= int32(limit)) {
		return days
	}
	return int32(limit)
}

// PlanLimitError is returned when adding one more of something would pass
// the plan's limit.
type PlanLimitError struct {
	Kind  LimitKind
	Limit int
	Plan  string
}

func (e *PlanLimitError) Error() string {
	label := limitLabels[e.Kind][1]
	if e.Limit == 1 {
		label = limitLabels[e.Kind][0]
	}
	return fmt.Sprintf("Your %s plan includes up to %d %s. Remove one or upgrade your plan to add more.", e.Plan, e.Limit, label)
}

// LicenseService answers "what plan is this" and "may we add one more".
type LicenseService struct {
	pool    *pgxpool.Pool
	license License
}

func NewLicenseService(pool *pgxpool.Pool, license License) *LicenseService {
	return &LicenseService{pool: pool, license: license}
}

func (s *LicenseService) License() License { return s.license }

// Usage counts what currently counts against each limit: active (not
// deleted) resources of each type, and active users.
func (s *LicenseService) Usage(ctx context.Context) (map[LimitKind]int, error) {
	usage := map[LimitKind]int{}
	rows, err := s.pool.Query(ctx, `SELECT resource_type, count(*) FROM resources WHERE deleted_at IS NULL GROUP BY resource_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byType := map[string]LimitKind{"VM": LimitVMs, "DATABASE": LimitDatabases, "OBJECT_STORAGE": LimitObjectStorage, "DOCKER_HOST": LimitDockerHosts, "K8S_CLUSTER": LimitK8sClusters}
	for rows.Next() {
		var t string
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return nil, err
		}
		if k, ok := byType[t]; ok {
			usage[k] = n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var users int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE deleted_at IS NULL AND is_active`).Scan(&users); err != nil {
		return nil, err
	}
	usage[LimitUsers] = users
	return usage, nil
}

// CheckCanAdd returns a *PlanLimitError when one more of kind would pass
// the plan's limit.
func (s *LicenseService) CheckCanAdd(ctx context.Context, kind LimitKind) error {
	limit, ok := s.license.Plan.Limits[kind]
	if !ok || limit == Unlimited {
		return nil
	}
	usage, err := s.Usage(ctx)
	if err != nil {
		return err
	}
	if usage[kind] >= limit {
		return &PlanLimitError{Kind: kind, Limit: limit, Plan: s.license.Plan.Name}
	}
	return nil
}

// IsPlanLimit reports whether err is a plan-limit refusal.
func IsPlanLimit(err error) bool {
	var e *PlanLimitError
	return errors.As(err, &e)
}
