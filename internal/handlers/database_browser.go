package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// DatabaseBrowserHandler implements database catalog/schema/table
// browsing endpoints (spec §21-28/§69-70): read-only, safe, paginated
// access to database structure and data. Every endpoint requires
// database.browser specifically (spec §54: "Do not automatically give
// Members table/document/key browsing... if Member does not have
// database.browser, Browser hidden/denied") -- a Member with only
// database.view/database.performance is correctly denied here even
// though they can see the database's monitoring dashboard.
type DatabaseBrowserHandler struct {
	store          *repository.Store
	browserService *services.DatabaseBrowserService
	authz          *services.AuthorizationService
}

// NewDatabaseBrowserHandler creates a browser handler.
func NewDatabaseBrowserHandler(store *repository.Store, browserService *services.DatabaseBrowserService, authz *services.AuthorizationService) *DatabaseBrowserHandler {
	return &DatabaseBrowserHandler{store: store, browserService: browserService, authz: authz}
}

// authorizeDatabase resolves :databaseId and verifies the caller holds
// requiredPermission on the database's owning resource -- 404-not-403 on
// any failure (existence must not be disclosed to an unauthorized
// caller), never a bare lookup by database ID alone (spec §57's "do not
// trust database ID from frontend").
func (h *DatabaseBrowserHandler) authorizeDatabase(w http.ResponseWriter, r *http.Request, requiredPermission string) (generated.Database, bool) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return generated.Database{}, false
	}
	databaseID, err := uuid.Parse(r.PathValue("databaseId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "database not found")
		return generated.Database{}, false
	}
	db, err := h.store.GetDatabaseByID(r.Context(), databaseID)
	if err != nil || db.DeletedAt.Valid {
		httpx.WriteError(w, http.StatusNotFound, "database not found")
		return generated.Database{}, false
	}
	allowed, err := h.authz.CanAccessDatabase(r.Context(), user, db.ResourceID, requiredPermission)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return generated.Database{}, false
	}
	if !allowed {
		httpx.WriteError(w, http.StatusNotFound, "database not found")
		return generated.Database{}, false
	}
	return db, true
}

// --- Request/Response types ---

type catalogEntryDTO struct {
	Name            string `json:"name"`
	ConnectionCount int64  `json:"connection_count"`
}

type catalogResponse struct {
	Databases []catalogEntryDTO `json:"databases"`
}

type schemasResponse struct {
	Schemas []string `json:"schemas"`
}

type tablesResponse struct {
	Tables []tableListItem `json:"tables"`
}

type tableListItem struct {
	Name      string `json:"name"`
	RowCount  int64  `json:"row_count,omitempty"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
}

type indexItemDTO struct {
	Name      string   `json:"name"`
	Columns   []string `json:"columns"`
	IsUnique  bool     `json:"is_unique"`
	IsPrimary bool     `json:"is_primary"`
}

type columnsResponse struct {
	Columns []columnItem `json:"columns"`
}

type columnItem struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
	Default  string `json:"default,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

type rowsResponse struct {
	Rows     []map[string]interface{} `json:"rows"`
	Total    int                      `json:"total"`
	PageSize int                      `json:"page_size"`
	Offset   int                      `json:"offset"`
	HasMore  bool                     `json:"has_more"`
}

// --- Database catalog endpoint ---
// GET /api/databases/:databaseId/catalog
func (h *DatabaseBrowserHandler) GetCatalog(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseBrowser)
	if !ok {
		return
	}
	databases, err := h.browserService.ListDatabases(r.Context(), db.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to list databases")
		return
	}
	items := make([]catalogEntryDTO, 0, len(databases))
	for _, d := range databases {
		items = append(items, catalogEntryDTO{Name: d.Name, ConnectionCount: d.ConnectionCount})
	}
	httpx.WriteJSON(w, http.StatusOK, catalogResponse{Databases: items})
}

// --- Schemas endpoint ---
// GET /api/databases/:databaseId/schemas (PostgreSQL only)
func (h *DatabaseBrowserHandler) GetSchemas(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseBrowser)
	if !ok {
		return
	}
	targetDatabase := r.URL.Query().Get("database")
	schemas, err := h.browserService.ListSchemas(r.Context(), db.ID, targetDatabase)
	if err != nil {
		if errors.Is(err, services.ErrBrowserNotSupported) {
			httpx.WriteError(w, http.StatusBadRequest, "schemas not supported for this database type")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to list schemas")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, schemasResponse{Schemas: schemas})
}

// --- Tables endpoint ---
// GET /api/databases/:databaseId/tables
func (h *DatabaseBrowserHandler) GetTables(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseBrowser)
	if !ok {
		return
	}
	schema := r.URL.Query().Get("schema")
	targetDatabase := r.URL.Query().Get("database")

	tables, err := h.browserService.ListTables(r.Context(), db.ID, schema, targetDatabase)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to list tables")
		return
	}
	items := make([]tableListItem, 0, len(tables))
	for _, t := range tables {
		items = append(items, tableListItem{Name: t.Name, RowCount: t.RowCount, SizeBytes: t.SizeBytes})
	}
	httpx.WriteJSON(w, http.StatusOK, tablesResponse{Tables: items})
}

// --- Columns endpoint ---
// GET /api/databases/:databaseId/tables/:tableId/columns
func (h *DatabaseBrowserHandler) GetColumns(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseBrowser)
	if !ok {
		return
	}
	tableName := r.PathValue("tableId")
	schema := r.URL.Query().Get("schema")
	targetDatabase := r.URL.Query().Get("database")

	columns, err := h.browserService.ListColumns(r.Context(), db.ID, schema, tableName, targetDatabase)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to list columns")
		return
	}
	items := make([]columnItem, 0, len(columns))
	for _, c := range columns {
		items = append(items, columnItem{Name: c.Name, Type: c.Type, Nullable: c.Nullable, Default: c.Default, Comment: c.Comment})
	}
	httpx.WriteJSON(w, http.StatusOK, columnsResponse{Columns: items})
}

// --- Rows endpoint ---
// GET /api/databases/:databaseId/tables/:tableId/rows (default 50, max 200 -- server enforced)
func (h *DatabaseBrowserHandler) GetTableRows(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseBrowser)
	if !ok {
		return
	}
	tableName := r.PathValue("tableId")
	schema := r.URL.Query().Get("schema")

	limit := services.DefaultBrowserRowLimit
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > services.MaxBrowserRowLimit {
		limit = services.MaxBrowserRowLimit
	}
	offset := 0
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	targetDatabase := r.URL.Query().Get("database")

	rows, err := h.browserService.GetTableRows(r.Context(), db.ID, schema, tableName, limit, offset, targetDatabase)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to query table rows")
		return
	}
	rowsArray := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		rowsArray = append(rowsArray, row.Values)
	}
	httpx.WriteJSON(w, http.StatusOK, rowsResponse{Rows: rowsArray, PageSize: limit, Offset: offset, HasMore: len(rows) >= limit})
}

// --- Search endpoint ---
// GET /api/databases/:databaseId/tables/:tableId/search
func (h *DatabaseBrowserHandler) SearchTable(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseBrowser)
	if !ok {
		return
	}
	tableName := r.PathValue("tableId")
	schema := r.URL.Query().Get("schema")
	searchQuery := r.URL.Query().Get("q")
	column := r.URL.Query().Get("column")

	limit := services.DefaultBrowserRowLimit
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= services.MaxBrowserRowLimit {
			limit = parsed
		}
	}

	targetDatabase := r.URL.Query().Get("database")
	rows, err := h.browserService.SearchTableData(r.Context(), db.ID, schema, tableName, column, searchQuery, limit, offset, targetDatabase)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "search failed")
		return
	}
	rowsArray := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		rowsArray = append(rowsArray, row.Values)
	}
	httpx.WriteJSON(w, http.StatusOK, rowsResponse{Rows: rowsArray, PageSize: limit, Offset: offset, HasMore: len(rows) >= limit})
}

// --- Index endpoint ---
// GET /api/databases/:databaseId/tables/:tableId/indexes (PostgreSQL)
func (h *DatabaseBrowserHandler) GetIndexes(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseBrowser)
	if !ok {
		return
	}
	tableName := r.PathValue("tableId")
	schema := r.URL.Query().Get("schema")
	targetDatabase := r.URL.Query().Get("database")

	indexes, err := h.browserService.ListIndexes(r.Context(), db.ID, schema, tableName, targetDatabase)
	if err != nil {
		if errors.Is(err, services.ErrBrowserNotSupported) {
			httpx.WriteError(w, http.StatusBadRequest, "indexes not supported for this database type")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to list indexes")
		return
	}
	items := make([]indexItemDTO, 0, len(indexes))
	for _, idx := range indexes {
		items = append(items, indexItemDTO{Name: idx.Name, Columns: idx.Columns, IsUnique: idx.IsUnique, IsPrimary: idx.IsPrimary})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]interface{}{"indexes": items})
}

// --- Logs endpoint ---
// GET /api/databases/:databaseId/logs -- requires database.logs
// specifically (spec §55), a separate permission from database.browser.
func (h *DatabaseBrowserHandler) GetLogs(w http.ResponseWriter, r *http.Request) {
	db, ok := h.authorizeDatabase(w, r, services.PermDatabaseLogs)
	if !ok {
		return
	}
	logType := r.URL.Query().Get("type")
	fromTime := r.URL.Query().Get("from")
	toTime := r.URL.Query().Get("to")
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	// Never fabricates logs (spec §29/#34): a provider/database that
	// doesn't expose logs reports ErrBrowserNotSupported, surfaced below
	// as "logs are not available for this database," never an empty list
	// pretending to be "no logs yet."
	logs, err := h.browserService.GetLogs(r.Context(), db.ID, logType, fromTime, toTime, limit)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrBrowserNotSupported),
			errors.Is(err, services.ErrDatabaseLogsUnsupported),
			errors.Is(err, services.ErrDatabaseLogsNotConfigured),
			errors.Is(err, services.ErrDatabaseQueryFailed):
			// These carry a specific, actionable message of their own
			// (e.g. "enable csvlog...", "grant pg_read_server_files...",
			// or the server's own rejected-query text) -- surface it
			// verbatim rather than a generic dead end.
			httpx.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		// Anything else reaching here is a real connect-level failure
		// (dial/auth/timeout/TLS) or an unexpected internal error.
		// Classify connect-level failures into the same coarse, safe
		// vocabulary Test/TestConnection use -- never the raw error,
		// which can embed a connection string (see
		// ConnectionStatusFromError's own doc comment) -- so this no
		// longer silently collapses into one opaque "failed to fetch
		// logs" for every kind of failure.
		if msg, ok := connectionErrorMessage(err); ok {
			httpx.WriteError(w, http.StatusBadGateway, msg)
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to fetch logs")
		return
	}
	logEntries := make([]map[string]interface{}, len(logs))
	for i, log := range logs {
		logEntries[i] = map[string]interface{}{"timestamp": log.Timestamp, "severity": log.Severity, "source": log.Source, "message": log.Message}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]interface{}{"logs": logEntries, "has_more": len(logs) >= limit})
}

// connectionErrorMessage classifies a direct-connection failure into a
// safe, static message -- mirrors DatabaseHandler.Test's use of
// services.ConnectionStatusFromError, just with a human sentence per
// status instead of a bare enum, since this endpoint (unlike Test) has
// nowhere else to put "why."
func connectionErrorMessage(err error) (string, bool) {
	switch services.ConnectionStatusFromError(err) {
	case services.ConnAUTHFAILED:
		return "The monitoring credential was rejected by the database server.", true
	case services.ConnTIMEOUT:
		return "Connecting to the database server timed out.", true
	case services.ConnTLSERROR:
		return "A TLS/SSL error occurred connecting to the database server.", true
	case services.ConnREFUSED:
		return "Could not reach the database server.", true
	default:
		return "", false
	}
}
