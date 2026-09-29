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
	ErrDatabaseInvalidType = errors.New("invalid database type")
	ErrDatabaseNotFound    = errors.New("database not found")
	ErrDatabaseInvalidHost = errors.New("invalid database host")
	ErrDatabaseInvalidPort = errors.New("invalid database port")
)

var validDatabaseTypes = map[string]bool{
	string(DBTypePostgreSQL): true, string(DBTypeMySQL): true, string(DBTypeMariaDB): true,
	string(DBTypeMongoDB): true, string(DBTypeRedis): true, string(DBTypeValkey): true,
}

// DatabaseService is the CRUD/configuration layer for standalone
// databases (spec §5/§6): a database is a first-class resource under a
// Workspace, never a VM child (spec §1's explicit "Do NOT make
// VM -> Database the required architecture").
type DatabaseService struct {
	store       *repository.Store
	credentials *StandaloneDatabaseCredentialService
}

// NewDatabaseService creates a DatabaseService.
func NewDatabaseService(store *repository.Store, credentials *StandaloneDatabaseCredentialService) *DatabaseService {
	return &DatabaseService{store: store, credentials: credentials}
}

// ConfigureInput is POST /api/databases's request shape (spec §6) --
// host/port/credentials plus provider metadata. Deliberately has no
// "query"/"command" field anywhere.
type ConfigureInput struct {
	WorkspaceID       uuid.UUID
	Name              string
	Type              string
	Provider          string
	Host              string
	Port              int32
	DatabaseName      string
	Region            string
	ClusterIdentifier string
	Endpoint          string
	TLSEnabled        bool
	TLSSkipVerify     bool
	Username          string
	Password          string
}

// Configure creates a new standalone database: a `resources` row
// (resource_type=DATABASE, under the given project/group) plus its
// `databases` row, atomically -- mirrors VMService.Create's transaction
// shape exactly. Stores the monitoring credential, if supplied, in the
// same call.
func (s *DatabaseService) Configure(ctx context.Context, in ConfigureInput) (generated.Database, error) {
	if !validDatabaseTypes[in.Type] {
		return generated.Database{}, ErrDatabaseInvalidType
	}
	if in.Host == "" {
		return generated.Database{}, ErrDatabaseInvalidHost
	}
	if in.Port <= 0 || in.Port > 65535 {
		return generated.Database{}, ErrDatabaseInvalidPort
	}
	name := in.Name
	if name == "" {
		name = in.Type
	}
	if _, err := s.store.GetWorkspaceByID(ctx, in.WorkspaceID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.Database{}, fmt.Errorf("%w: workspace", ErrNotFound)
		}
		return generated.Database{}, fmt.Errorf("load workspace: %w", err)
	}

	var db generated.Database
	err := s.store.WithTx(ctx, func(q *generated.Queries) error {
		resource, err := q.CreateResource(ctx, generated.CreateResourceParams{
			WorkspaceID: in.WorkspaceID, Name: name, ResourceType: "DATABASE",
		})
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: a resource named %q already exists", ErrDuplicateName, name)
			}
			return fmt.Errorf("create resource: %w", err)
		}

		created, err := q.CreateDatabaseResource(ctx, generated.CreateDatabaseResourceParams{
			ResourceID: resource.ID, Engine: in.Type, Host: in.Host, Port: in.Port,
			DatabaseName: pgutil.Text(in.DatabaseName), Username: pgutil.Text(in.Username), SslEnabled: in.TLSEnabled,
		})
		if err != nil {
			return fmt.Errorf("create database: %w", err)
		}

		updated, err := q.UpdateDatabaseConfig(ctx, generated.UpdateDatabaseConfigParams{
			ID: created.ID, Type: in.Type, Host: in.Host, Port: in.Port,
			DatabaseName: pgutil.Text(in.DatabaseName), Provider: pgutil.Text(in.Provider), Region: pgutil.Text(in.Region),
			ClusterIdentifier: pgutil.Text(in.ClusterIdentifier), Endpoint: pgutil.Text(in.Endpoint),
			TlsEnabled: in.TLSEnabled, TlsSkipVerify: in.TLSSkipVerify,
		})
		if err != nil {
			return fmt.Errorf("configure database: %w", err)
		}
		db = updated
		return nil
	})
	if err != nil {
		return generated.Database{}, err
	}

	if in.Username != "" || in.Password != "" {
		if err := s.credentials.SetCredential(ctx, db.ID, in.Username, in.Password); err != nil {
			return db, fmt.Errorf("store monitoring credential: %w", err)
		}
		// Monitoring is off by default (migrations/023) and both metrics
		// schedulers skip any row where it's off, forever, with no
		// "collect once on connect" hook -- so without this, a freshly
		// connected database silently never collects anything until
		// someone finds and flips the separate Overview-tab toggle. A
		// credential was just supplied specifically to enable collection,
		// so turn it on now rather than leaving that as a second,
		// easy-to-miss manual step.
		if enabled, err := s.SetMonitoringEnabled(ctx, db.ID, true); err == nil {
			db = enabled
		}
	}
	return db, nil
}

// UpdateInput is PATCH /api/databases/:id's request shape -- every field
// optional, only supplied fields change.
type UpdateInput struct {
	Type              *string
	Host              *string
	Port              *int32
	DatabaseName      *string
	Provider          *string
	Region            *string
	ClusterIdentifier *string
	Endpoint          *string
	TLSEnabled        *bool
	TLSSkipVerify     *bool
}

// Update edits a standalone database's connection details. Type/Host/Port/
// TLSEnabled/TLSSkipVerify are NOT NULL columns at the schema level, so a
// partial update first loads the current row and only overrides the
// fields the caller actually supplied -- the underlying UPDATE always
// writes a real, fully-resolved value for these five, never a
// placeholder NULL (unlike the four genuinely-nullable provider-metadata
// fields below, which use SQL's own COALESCE($n, col) for "leave
// unchanged").
func (s *DatabaseService) Update(ctx context.Context, databaseID uuid.UUID, in UpdateInput) (generated.Database, error) {
	if in.Type != nil && !validDatabaseTypes[*in.Type] {
		return generated.Database{}, ErrDatabaseInvalidType
	}
	current, err := s.store.GetDatabaseByID(ctx, databaseID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.Database{}, ErrDatabaseNotFound
		}
		return generated.Database{}, fmt.Errorf("load database: %w", err)
	}

	params := generated.UpdateDatabaseConfigParams{
		ID: databaseID, Type: current.Type, Host: current.Host, Port: current.Port,
		TlsEnabled: current.TlsEnabled, TlsSkipVerify: current.TlsSkipVerify,
	}
	if in.Type != nil {
		params.Type = *in.Type
	}
	if in.Host != nil {
		params.Host = *in.Host
	}
	if in.Port != nil {
		params.Port = *in.Port
	}
	if in.TLSEnabled != nil {
		params.TlsEnabled = *in.TLSEnabled
	}
	if in.TLSSkipVerify != nil {
		params.TlsSkipVerify = *in.TLSSkipVerify
	}
	// Not pgutil.Text below: that collapses "" to SQL NULL, which
	// UpdateDatabaseConfig's COALESCE reads as "leave unchanged" -- making
	// it impossible to ever clear one of these optional fields back to ""
	// once set (see the identical fix in object_storage_service.go/
	// k8s_cluster.go). An explicit field here always means "set it to
	// exactly this", including empty.
	if in.DatabaseName != nil {
		params.DatabaseName = pgtype.Text{String: *in.DatabaseName, Valid: true}
	}
	if in.Provider != nil {
		params.Provider = pgtype.Text{String: *in.Provider, Valid: true}
	}
	if in.Region != nil {
		params.Region = pgtype.Text{String: *in.Region, Valid: true}
	}
	if in.ClusterIdentifier != nil {
		params.ClusterIdentifier = pgtype.Text{String: *in.ClusterIdentifier, Valid: true}
	}
	if in.Endpoint != nil {
		params.Endpoint = pgtype.Text{String: *in.Endpoint, Valid: true}
	}
	updated, err := s.store.UpdateDatabaseConfig(ctx, params)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.Database{}, ErrDatabaseNotFound
		}
		return generated.Database{}, fmt.Errorf("update database: %w", err)
	}
	return updated, nil
}

// SetMonitoringEnabled turns metric collection on/off -- disabling stops
// the scheduler from ever enqueueing this database again, but never
// deletes historical metrics.
func (s *DatabaseService) SetMonitoringEnabled(ctx context.Context, databaseID uuid.UUID, enabled bool) (generated.Database, error) {
	return s.store.SetDatabaseMonitoringEnabled(ctx, generated.SetDatabaseMonitoringEnabledParams{ID: databaseID, MonitoringEnabled: enabled})
}

// Delete soft-deletes a database (spec §82): removes the monitoring
// *configuration* only -- never drops the real external database, and
// retains historical metrics per the retention policy.
func (s *DatabaseService) Delete(ctx context.Context, databaseID uuid.UUID) error {
	if err := s.store.SoftDeleteDatabaseResource(ctx, databaseID); err != nil {
		return err
	}
	return nil
}

// DatabaseAccessEntry is one user's effective access to a single standalone
// database, for the Database-scoped "Authorized Members" view (Step 18) --
// mirrors VMService's VMAccessEntry exactly (see services/vm.go), since
// this codebase's established pattern for VM/Database/ObjectStorage access
// listing is per-type duplication, not a shared generic abstraction.
type DatabaseAccessEntry struct {
	UserID      uuid.UUID
	Name        string
	Email       string
	Permissions []string
	Source      AccessSource
}

// ListAccess returns every user with access to databaseResourceID -- direct
// grants merged with the database's group members (if it belongs to an
// active group), using the same merge rule as VMService.ListAccess: a user
// with both direct and group access is reported once, as DIRECT, with the
// union of permissions. Group membership grants exactly
// {database.view, database.performance} -- the same fixed pair
// AuthorizationService.EffectiveDatabaseAccess already grants; it never
// includes database.browser/logs/query_details, which must be granted
// directly.
func (s *DatabaseService) ListAccess(ctx context.Context, databaseResourceID uuid.UUID) ([]DatabaseAccessEntry, error) {
	resource, err := s.store.GetDatabaseResourceByID(ctx, databaseResourceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("load database: %w", err)
	}

	merged := map[uuid.UUID]*DatabaseAccessEntry{}

	directRows, err := s.store.ListDirectAccessForResource(ctx, databaseResourceID)
	if err != nil {
		return nil, fmt.Errorf("list direct access: %w", err)
	}
	for _, row := range directRows {
		entry, ok := merged[row.UserID]
		if !ok {
			entry = &DatabaseAccessEntry{UserID: row.UserID, Name: row.Name, Email: row.Email, Source: SourceDirect}
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
			merged[m.ID] = &DatabaseAccessEntry{
				UserID: m.ID, Name: m.Name, Email: m.Email,
				Permissions: []string{PermDatabaseView, PermDatabasePerformance}, Source: SourceWorkspace,
			}
			continue
		}
		entry.Permissions = appendUnique(entry.Permissions, PermDatabaseView, PermDatabasePerformance)
	}

	result := make([]DatabaseAccessEntry, 0, len(merged))
	for _, entry := range merged {
		sort.Strings(entry.Permissions)
		result = append(result, *entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Email < result[j].Email })
	return result, nil
}
