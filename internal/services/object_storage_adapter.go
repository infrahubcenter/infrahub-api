package services

import (
	"context"
	"errors"
	"time"
)

// ObjectStorageConnection describes how to reach one standalone object
// storage bucket -- AWS S3, DigitalOcean Spaces, MinIO, or a generic
// S3-compatible endpoint. All four speak the same S3 API (spec/plan
// decision #1), so unlike the four standalone database engines this is
// one client shape configured per-provider via s3_client.go's Options,
// never four separate adapters.
type ObjectStorageConnection struct {
	Provider        string
	Endpoint        string
	Region          string
	Bucket          string
	BasePath        string
	AccessKeyID     string
	SecretAccessKey string
	TLSEnabled      bool
	TLSSkipVerify   bool
	ConnectTimeout  time.Duration
	CommandTimeout  time.Duration
}

// Typed adapter errors -- callers classify on these rather than parsing
// error strings; the frontend only ever sees the resulting
// ObjectStorageConnectionStatus enum, never these Go error values
// directly, and never the raw AWS SDK error string (which can embed the
// endpoint/query details).
var (
	ErrObjectStorageAuth         = errors.New("object storage authentication failed")
	ErrObjectStorageAccessDenied = errors.New("object storage access denied")
	ErrObjectStorageNotFound     = errors.New("object storage bucket not found")
	ErrObjectStorageConnection   = errors.New("object storage connection refused or unreachable")
	ErrObjectStorageTimeout      = errors.New("object storage connection timed out")
	ErrObjectStorageTLS          = errors.New("object storage TLS handshake failed")
	ErrObjectStorageUnsupported  = errors.New("object storage provider not supported")
)

// ObjectStorageConnectionStatus is the connectivity outcome of a
// HeadBucket probe against a standalone object storage bucket --
// deliberately an 8-value enum distinct from databases' 7-value
// ConnectionTestStatus (migration 026): ACCESS_DENIED and NOT_FOUND are
// meaningful, distinct S3 outcomes with no database analogue.
type ObjectStorageConnectionStatus string

const (
	ObjectStorageStatusConnected    ObjectStorageConnectionStatus = "CONNECTED"
	ObjectStorageStatusAuthFailed   ObjectStorageConnectionStatus = "AUTH_FAILED"
	ObjectStorageStatusAccessDenied ObjectStorageConnectionStatus = "ACCESS_DENIED"
	ObjectStorageStatusNotFound     ObjectStorageConnectionStatus = "NOT_FOUND"
	ObjectStorageStatusTimeout      ObjectStorageConnectionStatus = "TIMEOUT"
	ObjectStorageStatusTLSError     ObjectStorageConnectionStatus = "TLS_ERROR"
	ObjectStorageStatusUnavailable  ObjectStorageConnectionStatus = "UNAVAILABLE"
	ObjectStorageStatusUnknown      ObjectStorageConnectionStatus = "UNKNOWN"
)

// ObjectStorageConnectionStatusFromError classifies a connection-test
// error into an ObjectStorageConnectionStatus -- callers persist/display
// the resulting status, never the raw Go error (which could contain
// provider-specific request/endpoint detail). Mirrors
// ConnectionStatusFromError (database_health.go) exactly.
func ObjectStorageConnectionStatusFromError(err error) ObjectStorageConnectionStatus {
	switch {
	case err == nil:
		return ObjectStorageStatusConnected
	case errors.Is(err, ErrObjectStorageAuth):
		return ObjectStorageStatusAuthFailed
	case errors.Is(err, ErrObjectStorageAccessDenied):
		return ObjectStorageStatusAccessDenied
	case errors.Is(err, ErrObjectStorageNotFound):
		return ObjectStorageStatusNotFound
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, ErrObjectStorageTimeout):
		return ObjectStorageStatusTimeout
	case errors.Is(err, ErrObjectStorageTLS):
		return ObjectStorageStatusTLSError
	case errors.Is(err, ErrObjectStorageConnection):
		return ObjectStorageStatusUnavailable
	default:
		return ObjectStorageStatusUnknown
	}
}

// ObjectStorageMetricsResult is CollectObjectStorageMetrics's fast-cycle
// output (Step 17 Phase 2): a single HeadBucket probe's reachability,
// round-trip latency, and error count -- every field a pointer so "not
// collected" is representable and never coerced to a fake zero/false.
// Deliberately excludes object_count/total_size_bytes/requests/4xx/5xx --
// those are Phase 3's deep-cycle, bucket-scan responsibility and must
// never be pulled forward into the fast, HeadBucket-only cycle.
type ObjectStorageMetricsResult struct {
	BucketReachable  *bool
	RequestLatencyMs *float64
	ErrorCount       *int64
}

// ObjectStorageDeepMetricsResult is CollectObjectStorageDeepMetrics's
// slow-cycle output (Step 17 Phase 3): the bucket security-facts snapshot
// (versioning/encryption/public-access/object-lock, each a first-class
// UNKNOWN value that is set ONLY on positive evidence from a successful,
// independent API call -- a failed/denied call never gets interpreted as
// "probably disabled" or "probably private") plus best-effort bucket
// count/size/request metrics. ObjectCount/TotalSizeBytes/RequestCount/
// Error4xxCount/Error5xxCount stay nil when no source (CloudWatch or the
// bounded-listing fallback) could produce a number -- never a fabricated
// zero. Partial is true whenever ANY sub-probe failed (see Warning) or the
// bounded-listing fallback hit its page cap before reaching the end of the
// bucket, in which case ObjectCount/TotalSizeBytes are a real, honest
// undercount, never presented as authoritative.
type ObjectStorageDeepMetricsResult struct {
	ObjectCount      *int64
	TotalSizeBytes   *int64
	RequestCount     *int64
	Error4xxCount    *int64
	Error5xxCount    *int64
	VersioningStatus string // ENABLED | DISABLED | UNKNOWN
	EncryptionStatus string // ENABLED | DISABLED | UNKNOWN
	PublicAccess     string // PUBLIC | PRIVATE | UNKNOWN
	ObjectLockStatus string // ENABLED | DISABLED | UNKNOWN
	Partial          bool
	Warning          string
}

// ComputeObjectStorageHealth derives the fast-cycle-only health verdict
// from a HeadBucket connection status: reachable -> HEALTHY, an unclassified
// probe -> UNKNOWN, any classified failure -> CRITICAL. Deliberately
// simple/binary for Phase 2 -- unlike DatabaseHealthThresholds, no
// configurable warning/critical thresholds exist yet for object storage.
// Phase 3's deep cycle layers public-access/encryption/growth-based
// severity on top of this via its own recommendation sync, the same
// layering DatabaseDeepMetricsService uses on top of DatabaseMetricsService's
// own simple health call. The returned value is always one of the four
// strings object_storages.health_status's CHECK constraint allows
// (HEALTHY/WARNING/CRITICAL/UNKNOWN) -- WARNING is never produced by this
// function since no intermediate signal exists yet at the fast-cycle
// level.
func ComputeObjectStorageHealth(status ObjectStorageConnectionStatus) HealthStatus {
	switch status {
	case ObjectStorageStatusConnected:
		return HealthHealthy
	case ObjectStorageStatusUnknown:
		return HealthUnknown
	default:
		return HealthCritical
	}
}
