package services

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

var (
	ErrObjectStorageInvalidProvider = errors.New("invalid object storage provider")
	ErrObjectStorageInvalidBucket   = errors.New("invalid object storage bucket")
	ErrObjectStorageRecordNotFound  = errors.New("object storage not found")
)

var validObjectStorageProviders = map[string]bool{
	"AWS_S3": true, "DIGITALOCEAN_SPACES": true, "MINIO": true, "S3_COMPATIBLE": true,
}

// ObjectStorageService is the CRUD/configuration layer for standalone
// object storage: an object storage bucket is a first-class resource
// under a Workspace, never a VM child -- mirrors DatabaseService exactly.
// This phase implements CRUD + test-connection only; no write/delete/
// upload S3 API surface exists anywhere in this project.
type ObjectStorageService struct {
	store       *repository.Store
	credentials *StandaloneObjectStorageCredentialService
}

// NewObjectStorageService creates an ObjectStorageService.
func NewObjectStorageService(store *repository.Store, credentials *StandaloneObjectStorageCredentialService) *ObjectStorageService {
	return &ObjectStorageService{store: store, credentials: credentials}
}

// ConfigureObjectStorageInput is POST /api/object-storage's request shape:
// connection/provider metadata plus credentials. Deliberately has no
// write/delete/upload field anywhere.
type ConfigureObjectStorageInput struct {
	WorkspaceID     uuid.UUID
	Name            string
	Provider        string
	Endpoint        string
	Region          string
	Bucket          string
	BasePath        string
	TLSEnabled      bool
	TLSSkipVerify   bool
	AccessKeyID     string
	SecretAccessKey string
}

// Configure creates a new standalone object storage: a `resources` row
// (resource_type=OBJECT_STORAGE, under the given project/group) plus its
// `object_storages` row, atomically -- mirrors DatabaseService.Configure's
// transaction shape exactly. Stores the monitoring secret access key, if
// supplied, in the same call (after the transaction commits, same
// ordering as DatabaseService.Configure).
func (s *ObjectStorageService) Configure(ctx context.Context, in ConfigureObjectStorageInput) (generated.ObjectStorage, error) {
	if !validObjectStorageProviders[in.Provider] {
		return generated.ObjectStorage{}, ErrObjectStorageInvalidProvider
	}
	if in.Bucket == "" {
		return generated.ObjectStorage{}, ErrObjectStorageInvalidBucket
	}
	name := in.Name
	if name == "" {
		name = in.Bucket
	}
	if _, err := s.store.GetWorkspaceByID(ctx, in.WorkspaceID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.ObjectStorage{}, fmt.Errorf("%w: workspace", ErrNotFound)
		}
		return generated.ObjectStorage{}, fmt.Errorf("load workspace: %w", err)
	}

	var os generated.ObjectStorage
	err := s.store.WithTx(ctx, func(q *generated.Queries) error {
		resource, err := q.CreateResource(ctx, generated.CreateResourceParams{
			WorkspaceID: in.WorkspaceID, Name: name, ResourceType: "OBJECT_STORAGE",
		})
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: a resource named %q already exists", ErrDuplicateName, name)
			}
			return fmt.Errorf("create resource: %w", err)
		}

		created, err := q.CreateObjectStorage(ctx, generated.CreateObjectStorageParams{
			ResourceID: resource.ID, Provider: in.Provider, Endpoint: pgutil.Text(in.Endpoint), Region: pgutil.Text(in.Region),
			Bucket: in.Bucket, BasePath: pgutil.Text(in.BasePath), AccessKeyID: pgutil.Text(in.AccessKeyID),
		})
		if err != nil {
			return fmt.Errorf("create object storage: %w", err)
		}

		updated, err := q.UpdateObjectStorageConfig(ctx, generated.UpdateObjectStorageConfigParams{
			ID: created.ID, Name: pgutil.Text(name), TlsEnabled: pgutil.Bool(in.TLSEnabled), TlsSkipVerify: pgutil.Bool(in.TLSSkipVerify),
		})
		if err != nil {
			return fmt.Errorf("configure object storage: %w", err)
		}
		os = updated
		return nil
	})
	if err != nil {
		return generated.ObjectStorage{}, err
	}

	if in.SecretAccessKey != "" {
		if err := s.credentials.SetSecretKey(ctx, os.ID, in.SecretAccessKey); err != nil {
			return os, fmt.Errorf("store monitoring credential: %w", err)
		}
	}
	return os, nil
}

// UpdateObjectStorageInput is PATCH /api/object-storage/:id's request
// shape -- every field optional, only supplied fields change.
type UpdateObjectStorageInput struct {
	Name            *string
	Provider        *string
	Endpoint        *string
	Region          *string
	Bucket          *string
	BasePath        *string
	TLSEnabled      *bool
	TLSSkipVerify   *bool
	AccessKeyID     *string
	SecretAccessKey *string
}

// Update edits a standalone object storage's connection details --
// partial update via SQL's own COALESCE($n, col) for "leave unchanged",
// mirrors DatabaseService.Update's UpdateDatabaseConfig call exactly.
func (s *ObjectStorageService) Update(ctx context.Context, objectStorageID uuid.UUID, in UpdateObjectStorageInput) (generated.ObjectStorage, error) {
	if in.Provider != nil && !validObjectStorageProviders[*in.Provider] {
		return generated.ObjectStorage{}, ErrObjectStorageInvalidProvider
	}
	if in.Bucket != nil && *in.Bucket == "" {
		return generated.ObjectStorage{}, ErrObjectStorageInvalidBucket
	}

	params := generated.UpdateObjectStorageConfigParams{ID: objectStorageID}
	if in.Name != nil {
		params.Name = pgutil.Text(*in.Name)
	}
	if in.Provider != nil {
		params.Provider = pgutil.Text(*in.Provider)
	}
	if in.Endpoint != nil {
		// pgutil.Text collapses "" to SQL NULL (COALESCE's "leave unchanged"
		// sentinel), which would make clearing Endpoint/Region/BasePath back
		// to empty impossible through this endpoint -- a real gap once an
		// admin can actually edit an existing connection (previously this
		// input was create-only). A pointer being non-nil here already means
		// "the admin explicitly sent this field"; its string value (empty or
		// not) should be exactly what gets stored.
		params.Endpoint = pgtype.Text{String: *in.Endpoint, Valid: true}
	}
	if in.Region != nil {
		params.Region = pgtype.Text{String: *in.Region, Valid: true}
	}
	if in.Bucket != nil {
		params.Bucket = pgutil.Text(*in.Bucket)
	}
	if in.BasePath != nil {
		params.BasePath = pgtype.Text{String: *in.BasePath, Valid: true}
	}
	if in.TLSEnabled != nil {
		params.TlsEnabled = pgutil.Bool(*in.TLSEnabled)
	}
	if in.TLSSkipVerify != nil {
		params.TlsSkipVerify = pgutil.Bool(*in.TLSSkipVerify)
	}
	if in.AccessKeyID != nil {
		params.AccessKeyID = pgutil.Text(*in.AccessKeyID)
	}

	updated, err := s.store.UpdateObjectStorageConfig(ctx, params)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.ObjectStorage{}, ErrObjectStorageRecordNotFound
		}
		return generated.ObjectStorage{}, fmt.Errorf("update object storage: %w", err)
	}

	if in.SecretAccessKey != nil {
		if err := s.credentials.SetSecretKey(ctx, updated.ID, *in.SecretAccessKey); err != nil {
			return updated, fmt.Errorf("store monitoring credential: %w", err)
		}
	}
	return updated, nil
}

// SetMonitoringEnabled turns metric collection on/off -- disabling stops
// a future scheduler from ever enqueueing this object storage again, but
// never deletes historical metrics.
func (s *ObjectStorageService) SetMonitoringEnabled(ctx context.Context, objectStorageID uuid.UUID, enabled bool) (generated.ObjectStorage, error) {
	return s.store.SetObjectStorageMonitoringEnabled(ctx, generated.SetObjectStorageMonitoringEnabledParams{ID: objectStorageID, MonitoringEnabled: enabled})
}

// Delete soft-deletes an object storage's monitoring registration only.
// It NEVER touches the real S3 bucket or any object inside it -- this
// project has no write/delete/upload S3 API surface anywhere, and Delete
// here only clears Infra Hub Center's own monitoring configuration row,
// exactly like DatabaseService.Delete does for a standalone database.
func (s *ObjectStorageService) Delete(ctx context.Context, objectStorageID uuid.UUID) error {
	return s.store.SoftDeleteObjectStorageResource(ctx, objectStorageID)
}

// ObjectStorageAccessEntry is one user's effective access to a single
// standalone object storage, for the ObjectStorage-scoped "Authorized
// Members" view (Step 18) -- mirrors DatabaseService's DatabaseAccessEntry/
// VMService's VMAccessEntry exactly (per-type duplication, not a shared
// generic abstraction, matching this codebase's established pattern for
// this concern).
type ObjectStorageAccessEntry struct {
	UserID      uuid.UUID
	Name        string
	Email       string
	Permissions []string
	Source      AccessSource
}

// ListAccess returns every user with access to objectStorageResourceID --
// direct grants merged with the storage's group members (if it belongs to
// an active group), using the same merge rule as
// DatabaseService.ListAccess/VMService.ListAccess: a user with both direct
// and group access is reported once, as DIRECT, with the union of
// permissions. Group membership grants exactly
// {object_storage.view, object_storage.monitor} -- the same fixed pair
// AuthorizationService.EffectiveObjectStorageAccess already grants; it
// never includes object_storage.browser/download, which must be granted
// directly.
func (s *ObjectStorageService) ListAccess(ctx context.Context, objectStorageResourceID uuid.UUID) ([]ObjectStorageAccessEntry, error) {
	resource, err := s.store.GetObjectStorageResourceByID(ctx, objectStorageResourceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("load object storage: %w", err)
	}

	merged := map[uuid.UUID]*ObjectStorageAccessEntry{}

	directRows, err := s.store.ListDirectAccessForResource(ctx, objectStorageResourceID)
	if err != nil {
		return nil, fmt.Errorf("list direct access: %w", err)
	}
	for _, row := range directRows {
		entry, ok := merged[row.UserID]
		if !ok {
			entry = &ObjectStorageAccessEntry{UserID: row.UserID, Name: row.Name, Email: row.Email, Source: SourceDirect}
			merged[row.UserID] = entry
		}
		entry.Permissions = appendUnique(entry.Permissions, row.PermissionName)
	}

	members, err := s.store.ListWorkspaceMembers(ctx, resource.WorkspaceID)
	if err != nil {
		return nil, fmt.Errorf("list workspace members: %w", err)
	}
	for _, m := range members {
		entry, ok := merged[m.ID]
		if !ok {
			merged[m.ID] = &ObjectStorageAccessEntry{
				UserID: m.ID, Name: m.Name, Email: m.Email,
				Permissions: []string{PermObjectStorageView, PermObjectStorageMonitor}, Source: SourceWorkspace,
			}
			continue
		}
		entry.Permissions = appendUnique(entry.Permissions, PermObjectStorageView, PermObjectStorageMonitor)
	}

	result := make([]ObjectStorageAccessEntry, 0, len(merged))
	for _, entry := range merged {
		sort.Strings(entry.Permissions)
		result = append(result, *entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Email < result[j].Email })
	return result, nil
}
