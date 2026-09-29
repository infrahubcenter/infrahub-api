// Package services: log_archive.go is the optional step every log
// retention sweep (Docker/K8s/Docker Host, see docker_log_retention.go/
// k8s_log_retention.go/docker_host_log_retention.go) runs immediately
// before it deletes rows older than the configured retention window --
// writing them out somewhere durable first, so "the 30-day window
// closed" means "moved to long-term storage," not "gone." Off by
// default (LOG_ARCHIVE_BACKEND=none): existing behavior -- rows are just
// deleted -- is completely unchanged unless an operator opts in.
package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ArchivedLogLine is one row a retention sweep is about to delete,
// captured just before deletion. ParentID is whichever foreign key that
// table's rows carry (docker_container_id / k8s_pod_id /
// docker_host_container_sighting_id) -- deliberately untyped as a plain
// string here (not a uuid.UUID) since this struct's only job is to
// become one line of JSON, not to participate in any further query.
type ArchivedLogLine struct {
	ID       string    `json:"id"`
	ParentID string    `json:"parent_id"`
	LoggedAt time.Time `json:"logged_at"`
	Line     string    `json:"line"`
}

// LogArchiver writes a retention sweep's about-to-be-deleted rows
// somewhere durable. Configured once (NewLogArchiver, from
// LOG_ARCHIVE_BACKEND) and shared by all three retention services --
// every implementation writes the exact same newline-delimited JSON
// shape, one ArchivedLogLine per line, so an archive from any of the
// three sources can be inspected/grepped/re-ingested identically.
type LogArchiver interface {
	// Archive persists lines, grouped/named by table so three retention
	// services archiving concurrently never collide with each other.
	// Callers only ever call this with a non-empty slice -- there is
	// nothing to special-case for "nothing to archive this cycle."
	Archive(ctx context.Context, table string, lines []ArchivedLogLine) error
}

// LogArchiveConfig is LOG_ARCHIVE_BACKEND and friends, straight from
// internal/config.Config -- see cmd/server/main.go for where these are
// read from the environment (.env or the encrypted development.ini.enc/
// production.ini.enc, per internal/config/encrypted_env.go).
type LogArchiveConfig struct {
	Backend           string // "none" (default) | "volume" | "s3"
	VolumePath        string
	S3Bucket          string
	S3Region          string
	S3Endpoint        string // optional: non-AWS S3-compatible providers
	S3Prefix          string
	S3AccessKeyID     string
	S3SecretAccessKey string
}

// NewLogArchiver builds the one configured LogArchiver. Required fields
// for "volume"/"s3" are validated eagerly, at startup -- a
// misconfiguration surfaces immediately as a failure to start the
// server, not silently on the first retention sweep that happens to find
// rows to archive, hours or days later.
func NewLogArchiver(cfg LogArchiveConfig) (LogArchiver, error) {
	switch cfg.Backend {
	case "", "none":
		return noopLogArchiver{}, nil

	case "volume":
		if cfg.VolumePath == "" {
			return nil, fmt.Errorf("LOG_ARCHIVE_BACKEND=volume requires LOG_ARCHIVE_VOLUME_PATH")
		}
		if err := os.MkdirAll(cfg.VolumePath, 0o755); err != nil {
			return nil, fmt.Errorf("create log archive volume path %s: %w", cfg.VolumePath, err)
		}
		return &volumeLogArchiver{dir: cfg.VolumePath}, nil

	case "s3":
		if cfg.S3Bucket == "" || cfg.S3Region == "" || cfg.S3AccessKeyID == "" || cfg.S3SecretAccessKey == "" {
			return nil, fmt.Errorf("LOG_ARCHIVE_BACKEND=s3 requires LOG_ARCHIVE_S3_BUCKET, LOG_ARCHIVE_S3_REGION, LOG_ARCHIVE_S3_ACCESS_KEY_ID, and LOG_ARCHIVE_S3_SECRET_ACCESS_KEY")
		}
		// Reuses this app's existing S3 client shape (s3_client.go) --
		// the same AWS SDK v2 client every admin-registered Object
		// Storage connection already uses, just pointed at a fixed,
		// app-level archive bucket instead of a per-resource one.
		client, err := newS3Client(ObjectStorageConnection{
			Provider: "S3_COMPATIBLE", Endpoint: cfg.S3Endpoint, Region: cfg.S3Region,
			AccessKeyID: cfg.S3AccessKeyID, SecretAccessKey: cfg.S3SecretAccessKey,
		})
		if err != nil {
			return nil, fmt.Errorf("build log archive s3 client: %w", err)
		}
		return &s3LogArchiver{client: client, bucket: cfg.S3Bucket, prefix: cfg.S3Prefix}, nil

	default:
		return nil, fmt.Errorf("unknown LOG_ARCHIVE_BACKEND %q (must be none, volume, or s3)", cfg.Backend)
	}
}

// encodeNDJSON renders lines as newline-delimited JSON -- one
// ArchivedLogLine object per line, so a large archive can be
// streamed/grepped/re-ingested one line at a time rather than needing to
// parse one giant JSON array into memory.
func encodeNDJSON(lines []ArchivedLogLine) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, l := range lines {
		_ = enc.Encode(l) // ArchivedLogLine is all safe JSON types -- Encode cannot fail here
	}
	return buf.Bytes()
}

// noopLogArchiver is LOG_ARCHIVE_BACKEND=none (the default): rows are
// just deleted by the retention sweep, exactly as before this feature
// existed.
type noopLogArchiver struct{}

func (noopLogArchiver) Archive(ctx context.Context, table string, lines []ArchivedLogLine) error {
	return nil
}

// volumeLogArchiver appends NDJSON to a local (or mounted -- a Docker
// volume, most likely) directory: one growing file per (table, day), so
// repeated daily retention sweeps for the same table accumulate into one
// file instead of scattering one file per run.
type volumeLogArchiver struct {
	dir string
}

func (a *volumeLogArchiver) Archive(ctx context.Context, table string, lines []ArchivedLogLine) error {
	path := filepath.Join(a.dir, table+"-"+time.Now().UTC().Format("2006-01-02")+".ndjson")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(encodeNDJSON(lines)); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// s3LogArchiver uploads NDJSON to an S3-compatible bucket -- one object
// PER RETENTION SWEEP (S3 has no cheap append the way a local file does),
// under <prefix><table>/<day>/<unix-nano timestamp>.ndjson -- the
// timestamp keeps repeated same-day sweeps from ever colliding on the
// same key.
type s3LogArchiver struct {
	client *s3.Client
	bucket string
	prefix string
}

func (a *s3LogArchiver) Archive(ctx context.Context, table string, lines []ArchivedLogLine) error {
	now := time.Now().UTC()
	key := fmt.Sprintf("%s%s/%s/%d.ndjson", a.prefix, table, now.Format("2006-01-02"), now.UnixNano())
	body := encodeNDJSON(lines)
	_, err := a.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(a.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/x-ndjson"),
	})
	if err != nil {
		return fmt.Errorf("upload %s to s3://%s: %w", key, a.bucket, err)
	}
	return nil
}
