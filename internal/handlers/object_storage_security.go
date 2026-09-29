package handlers

import (
	"context"
	"net/http"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/services"
)

// This file implements Step 17 Phase 3's three read-only informational
// endpoints (GET .../security, .../growth, .../health) plus the shared
// helpers Get's embedded security/growth_projection/health_reasons fields
// also use -- mirrors object_storage_metrics.go's file-per-concern split.
// All three require object_storage.view (read-only, not the .monitor
// tier) and use authorizeObjectStorage's existing 404-not-403 IDOR
// discipline exactly like every other object-storage-scoped endpoint.

// objectStorageSecurityDTO is GET .../security's exact response shape --
// the four security-fact columns synced onto object_storages by the deep
// cycle (ObjectStorageDeepMetricsService.CollectDeep ->
// UpdateObjectStorageSecurityFacts), read directly off the row
// authorizeObjectStorage already loaded (no extra query, no join to
// object_storage_deep_metrics needed). Every field is always present and
// always one of ENABLED/DISABLED/UNKNOWN or PUBLIC/PRIVATE/UNKNOWN --
// UNKNOWN is a first-class value here, never omitted, since "we don't
// know yet" is itself meaningful information for this endpoint.
type objectStorageSecurityDTO struct {
	Versioning   string `json:"versioning"`
	Encryption   string `json:"encryption"`
	ObjectLock   string `json:"object_lock"`
	PublicAccess string `json:"public_access"`
}

func (h *ObjectStorageHandler) securityDTO(os generated.ObjectStorage) objectStorageSecurityDTO {
	return objectStorageSecurityDTO{
		Versioning: os.VersioningStatus, Encryption: os.EncryptionStatus,
		ObjectLock: os.ObjectLockStatus, PublicAccess: os.PublicAccess,
	}
}

// Security handles GET /api/object-storage/:id/security.
func (h *ObjectStorageHandler) Security(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageView)
	if !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.securityDTO(os))
}

// objectStorageGrowthDTO is GET .../growth's response shape.
// GrowthBytesPerDay/Estimated30dGrowthBytes are only ever both present or
// both absent together -- CollectDeep only computes a rate at all when
// ComputeGrowthRate had ≥7 days of real history to work with (spec: "don't
// claim guaranteed future growth" / "only with enough historical data");
// absent means exactly that, never a fabricated 0. CurrentBytes can be
// present independently (a storage can have a known current size before
// 7 days of history accumulates a growth rate).
type objectStorageGrowthDTO struct {
	CurrentBytes            *int64   `json:"current_bytes,omitempty"`
	GrowthBytesPerDay       *float64 `json:"growth_bytes_per_day,omitempty"`
	Estimated30dGrowthBytes *float64 `json:"estimated_30d_growth_bytes,omitempty"`
}

// growthDTO builds GET .../growth's payload without ever opening a new S3
// connection: current size prefers the shared fast/deep cache (the deep
// cycle merges its own freshly observed size into it -- see
// ObjectStorageMetricsCache.MergeBucketMetrics), falling back to the
// latest object_storage_metrics DB row; growth rate/projection comes from
// the latest object_storage_deep_metrics row. Returns nil when NOTHING is
// known at all (never monitored by a deep cycle yet), so callers can
// either embed it as an omitted field (Get's DTO) or return it as an
// empty JSON object (the dedicated endpoint, for a consistent "always 200,
// fields absent" contract with every other metrics-style endpoint in this
// handler).
func (h *ObjectStorageHandler) growthDTO(ctx context.Context, os generated.ObjectStorage) *objectStorageGrowthDTO {
	dto := objectStorageGrowthDTO{}
	if entry, found := h.cache.Get(os.ID); found {
		dto.CurrentBytes = entry.Snapshot.TotalSizeBytes
	}
	if dto.CurrentBytes == nil {
		if row, err := h.store.GetLatestObjectStorageMetric(ctx, os.ID); err == nil {
			dto.CurrentBytes = pgutil.Int8Ptr(row.TotalSizeBytes)
		}
	}
	if deepRow, err := h.store.GetLatestObjectStorageDeepMetric(ctx, os.ID); err == nil && deepRow.GrowthBytesPerDay.Valid {
		rate := deepRow.GrowthBytesPerDay.Float64
		dto.GrowthBytesPerDay = &rate
		estimated := rate * 30
		dto.Estimated30dGrowthBytes = &estimated
	}
	if dto.CurrentBytes == nil && dto.GrowthBytesPerDay == nil {
		return nil
	}
	return &dto
}

// Growth handles GET /api/object-storage/:id/growth. A storage with no
// deep-cycle history yet returns 200 with an empty JSON object, matching
// this handler's other metrics-style endpoints (never a 404 -- the
// storage itself exists and is authorized, only its growth data is
// absent).
func (h *ObjectStorageHandler) Growth(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageView)
	if !ok {
		return
	}
	dto := h.growthDTO(r.Context(), os)
	if dto == nil {
		dto = &objectStorageGrowthDTO{}
	}
	httpx.WriteJSON(w, http.StatusOK, dto)
}

// objectStorageHealthReasonText maps each of the four deep-cycle
// recommendation types this phase generates to the human-readable reason
// text GET .../health surfaces -- matches spec §31's example wording
// ("Public access detected", "Storage growth increased"). Deliberately
// the single source of truth for BOTH the reason text AND (via the active-
// recommendation lookup below) whether a condition is currently true --
// the exact same threshold math ObjectStorageDeepMetricsService.
// syncRecommendations already ran, never recomputed/duplicated here.
var objectStorageHealthReasonText = map[string]string{
	"OBJECT_STORAGE_PUBLIC_ACCESS":       "Public access detected",
	"OBJECT_STORAGE_ENCRYPTION_DISABLED": "Encryption disabled",
	"OBJECT_STORAGE_HIGH_GROWTH":         "Storage growth increased",
	"OBJECT_STORAGE_HIGH_ERROR_RATE":     "High error rate detected",
}

// objectStorageHealthDTO is GET .../health's response shape.
type objectStorageHealthDTO struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons"`
}

// computeObjectStorageHealth layers the deep cycle's currently-active
// recommendations on top of the fast cycle's own binary health verdict
// (os.HealthStatus: HEALTHY/CRITICAL/UNKNOWN, see
// ComputeObjectStorageHealth's doc comment) -- exactly the layering that
// function's own comment predicts ("Phase 3's deep cycle layers public-
// access/encryption/growth-based severity on top of this via its own
// recommendation sync"). A recommendation's severity only ever escalates
// the status (CRITICAL wins over WARNING wins over HEALTHY/UNKNOWN), never
// downgrades an existing CRITICAL (e.g. a genuinely unreachable bucket)
// back down to WARNING.
func (h *ObjectStorageHandler) computeObjectStorageHealth(ctx context.Context, os generated.ObjectStorage) (string, []string) {
	health := services.HealthStatus(os.HealthStatus)
	// Non-nil from the start -- encoding/json marshals a nil []string as
	// `null`, but the spec's `reasons: string[]` contract expects a real
	// (possibly empty) array even when nothing is wrong.
	reasons := []string{}

	if os.ConnectionStatus != "CONNECTED" && os.ConnectionStatus != "UNKNOWN" {
		reasons = append(reasons, "Bucket is unreachable")
	}

	recs, err := h.store.ListRecommendationsByResource(ctx, generated.ListRecommendationsByResourceParams{ResourceID: os.ResourceID, Status: ""})
	if err == nil {
		for _, rec := range recs {
			if rec.Status == "RESOLVED" || rec.Status == "DISMISSED" {
				continue
			}
			reason, known := objectStorageHealthReasonText[rec.Type]
			if !known {
				continue
			}
			reasons = append(reasons, reason)
			escalation := services.HealthWarning
			if rec.Severity == "CRITICAL" {
				escalation = services.HealthCritical
			}
			health = worseObjectStorageHealth(health, escalation)
		}
	}
	return string(health), reasons
}

// worseObjectStorageHealth returns whichever of a/b ranks worse
// (CRITICAL > WARNING > HEALTHY > UNKNOWN) -- a small, local helper rather
// than exporting services' own unexported severityRank, since this is the
// only place in the handlers package that needs it.
func worseObjectStorageHealth(a, b services.HealthStatus) services.HealthStatus {
	rank := func(s services.HealthStatus) int {
		switch s {
		case services.HealthCritical:
			return 3
		case services.HealthWarning:
			return 2
		case services.HealthHealthy:
			return 1
		default: // UNKNOWN
			return 0
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// Health handles GET /api/object-storage/:id/health.
func (h *ObjectStorageHandler) Health(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageView)
	if !ok {
		return
	}
	status, reasons := h.computeObjectStorageHealth(r.Context(), os)
	httpx.WriteJSON(w, http.StatusOK, objectStorageHealthDTO{Status: status, Reasons: reasons})
}
