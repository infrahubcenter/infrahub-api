// GET-vs-POST for the download endpoint: the plan's own Routes section
// spells out "POST .../objects/download (POST, not GET, per spec §48 --
// this creates a stateful/sensitive short-lived token)" -- an explicit,
// already-made routing decision in the approved plan, not an open
// question this phase re-litigates. A pure-statelessness argument for GET
// is genuinely defensible in the abstract (a presigned URL is a
// self-contained, side-effect-free computation -- generating one writes no
// server-side row), but the plan's own text ties the choice to spec §48's
// broader instruction about operations that mint access tokens, which this
// implementation defers to as written rather than overriding with its own
// re-derivation of the plan author's intent. RequestDownload below is
// therefore POST. This is a KNOWN DIVERGENCE from the frontend agent's
// contract (which assumes GET .../objects/download) -- flagged explicitly
// in this phase's delivery report for the two sides to reconcile.
package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// ObjectStorageBrowserHandler implements Step 17 Phase 4's read-only
// object browser: prefix/pseudo-folder listing, prefix-anchored search,
// object metadata, a short-lived presigned download URL, and a
// byte-capped text/JSON preview. Mirrors DatabaseBrowserHandler's shape
// exactly -- its own copy of authorizeObjectStorage (rather than sharing
// ObjectStorageHandler's), 404-not-403 on every authorization failure, and
// a distinct permission per endpoint tier: List/Search/GetObjectMetadata/
// GetPreview all require object_storage.browser; RequestDownload requires
// object_storage.download instead (NOT additionally object_storage.browser
// -- see RequestDownload's own doc comment for why). No write/delete/
// upload S3 call exists anywhere behind this handler.
type ObjectStorageBrowserHandler struct {
	store           *repository.Store
	authz           *services.AuthorizationService
	browser         *services.ObjectStorageBrowserService
	audit           *services.AuditService
	maxPageSize     int32
	previewMaxBytes int64
	downloadURLTTL  time.Duration
}

// NewObjectStorageBrowserHandler creates an ObjectStorageBrowserHandler.
func NewObjectStorageBrowserHandler(
	store *repository.Store, authz *services.AuthorizationService, browser *services.ObjectStorageBrowserService, audit *services.AuditService,
	maxPageSize int32, previewMaxBytes int64, downloadURLTTL time.Duration,
) *ObjectStorageBrowserHandler {
	return &ObjectStorageBrowserHandler{
		store: store, authz: authz, browser: browser, audit: audit,
		maxPageSize: maxPageSize, previewMaxBytes: previewMaxBytes, downloadURLTTL: downloadURLTTL,
	}
}

// authorizeObjectStorage resolves :id and verifies the caller holds
// requiredPermission on the object storage's owning resource --
// 404-not-403 on any failure, mirroring ObjectStorageHandler.
// authorizeObjectStorage / DatabaseBrowserHandler.authorizeDatabase
// exactly so existence is never disclosed to an unauthorized caller. Kept
// as this handler's own copy (rather than shared with ObjectStorageHandler)
// the same way DatabaseBrowserHandler keeps its own copy independent of
// DatabaseHandler's.
func (h *ObjectStorageBrowserHandler) authorizeObjectStorage(w http.ResponseWriter, r *http.Request, requiredPermission string) (generated.ObjectStorage, bool) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return generated.ObjectStorage{}, false
	}
	objectStorageID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "object storage not found")
		return generated.ObjectStorage{}, false
	}
	os, err := h.store.GetObjectStorageByID(r.Context(), objectStorageID)
	if err != nil || os.DeletedAt.Valid {
		httpx.WriteError(w, http.StatusNotFound, "object storage not found")
		return generated.ObjectStorage{}, false
	}
	allowed, err := h.authz.CanAccessObjectStorage(r.Context(), user, os.ResourceID, requiredPermission)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return generated.ObjectStorage{}, false
	}
	if !allowed {
		httpx.WriteError(w, http.StatusNotFound, "object storage not found")
		return generated.ObjectStorage{}, false
	}
	return os, true
}

// --- DTOs ---

type objectEntryDTO struct {
	Type         string  `json:"type"`
	Name         string  `json:"name"`
	Key          string  `json:"key"`
	SizeBytes    *int64  `json:"size_bytes,omitempty"`
	LastModified *string `json:"last_modified,omitempty"`
	StorageClass string  `json:"storage_class,omitempty"`
}

type objectListPageDTO struct {
	Bucket                string           `json:"bucket"`
	Prefix                string           `json:"prefix"`
	Entries               []objectEntryDTO `json:"entries"`
	NextContinuationToken string           `json:"next_continuation_token,omitempty"`
}

func toObjectListPageDTO(page services.ObjectListPage) objectListPageDTO {
	entries := make([]objectEntryDTO, 0, len(page.Entries))
	for _, e := range page.Entries {
		entries = append(entries, objectEntryDTO{
			Type: string(e.Type), Name: e.Name, Key: e.Key, SizeBytes: e.SizeBytes,
			LastModified: formatTimePtr(e.LastModified), StorageClass: e.StorageClass,
		})
	}
	return objectListPageDTO{
		Bucket: page.Bucket, Prefix: page.Prefix, Entries: entries, NextContinuationToken: page.NextContinuationToken,
	}
}

// formatTimePtr formats a *time.Time as RFC3339, or nil when absent --
// never a fabricated zero-value timestamp.
func formatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	formatted := t.Format(time.RFC3339)
	return &formatted
}

type objectMetadataDTO struct {
	Key          string            `json:"key"`
	SizeBytes    int64             `json:"size_bytes"`
	ContentType  string            `json:"content_type,omitempty"`
	ETag         string            `json:"etag,omitempty"`
	LastModified *string           `json:"last_modified,omitempty"`
	StorageClass string            `json:"storage_class,omitempty"`
	Metadata     map[string]string `json:"metadata"`
}

type objectDownloadDTO struct {
	URL       string `json:"url"`
	ExpiresAt string `json:"expires_at"`
}

type objectPreviewDTO struct {
	ContentType string `json:"content_type"`
	Encoding    string `json:"encoding"`
	Content     string `json:"content"`
	Truncated   bool   `json:"truncated"`
}

// --- query param parsing ---

// parsePageLimit clamps against this handler's configured
// OBJECT_STORAGE_MAX_PAGE_SIZE -- ObjectStorageBrowserService itself
// additionally re-clamps against its own compile-time MaxObjectPageSize
// ceiling, so a caller can never coax more than that absolute maximum out
// of either layer regardless of what "limit" it requests.
func (h *ObjectStorageBrowserHandler) parsePageLimit(r *http.Request) int {
	limit := services.DefaultObjectPageSize
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	maxAllowed := int(h.maxPageSize)
	if maxAllowed <= 0 {
		maxAllowed = services.MaxObjectPageSize
	}
	if limit > maxAllowed {
		limit = maxAllowed
	}
	return limit
}

// writeObjectStorageBrowserError classifies a services.ObjectStorage*
// browser error into an HTTP status. A genuinely missing key
// (ErrObjectStorageNotFound) is an honest 404 with a real "object not
// found" body -- unlike authorizeObjectStorage's deliberately
// existence-concealing 404, this one is a normal content-layer response
// about an object within an already-authorized, already-confirmed-to-exist
// storage, so it discloses nothing an authorized caller doesn't already
// know (they can already list the bucket). A malformed request
// (ErrObjectStorageInvalidPath) is 400. Preview-specific refusals
// (too-large / unsupported-content-type) get their own precise statuses.
// Every other classified S3-side failure (auth/access-denied/tls/
// connection) is 502 Bad Gateway -- an upstream problem, not the caller's
// fault -- except a timeout, which is the more precise 504.
func writeObjectStorageBrowserError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, services.ErrObjectStorageInvalidPath):
		httpx.WriteError(w, http.StatusBadRequest, "invalid prefix or key")
	case errors.Is(err, services.ErrObjectStoragePreviewTooLarge):
		httpx.WriteError(w, http.StatusRequestEntityTooLarge, "object is too large to preview")
	case errors.Is(err, services.ErrObjectStoragePreviewUnsupported):
		httpx.WriteError(w, http.StatusUnsupportedMediaType, "preview is not supported for this object's content type")
	case errors.Is(err, services.ErrObjectStorageNotFound):
		httpx.WriteError(w, http.StatusNotFound, "object not found")
	case errors.Is(err, services.ErrObjectStorageTimeout):
		httpx.WriteError(w, http.StatusGatewayTimeout, "object storage request timed out")
	case errors.Is(err, services.ErrObjectStorageAuth), errors.Is(err, services.ErrObjectStorageAccessDenied),
		errors.Is(err, services.ErrObjectStorageTLS), errors.Is(err, services.ErrObjectStorageConnection),
		errors.Is(err, services.ErrObjectStorageUnsupported):
		httpx.WriteError(w, http.StatusBadGateway, "object storage request failed")
	default:
		httpx.WriteError(w, http.StatusInternalServerError, "object storage request failed")
	}
}

// --- Endpoints ---

// ListObjects handles GET /api/object-storage/:id/objects.
func (h *ObjectStorageBrowserHandler) ListObjects(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageBrowser)
	if !ok {
		return
	}
	prefix := r.URL.Query().Get("prefix")
	continuationToken := r.URL.Query().Get("continuation_token")
	limit := h.parsePageLimit(r)

	page, err := h.browser.ListObjects(r.Context(), os.ID, prefix, continuationToken, limit)
	if err != nil {
		writeObjectStorageBrowserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toObjectListPageDTO(page))
}

// PrefixSize handles GET /api/object-storage/:id/objects/prefix-size?prefix=.
// Same permission as ListObjects (it's still just reading, one bounded
// recursive listing instead of one page) -- powers the Browser table's
// per-folder Size column, computed on demand rather than eagerly for every
// folder row on every page load.
func (h *ObjectStorageBrowserHandler) PrefixSize(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageBrowser)
	if !ok {
		return
	}
	prefix := r.URL.Query().Get("prefix")

	result, err := h.browser.GetPrefixSize(r.Context(), os.ID, prefix)
	if err != nil {
		writeObjectStorageBrowserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"object_count": result.ObjectCount, "total_size_bytes": result.TotalSizeBytes, "truncated": result.Truncated,
	})
}

// Search handles GET /api/object-storage/:id/objects/search.
func (h *ObjectStorageBrowserHandler) Search(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageBrowser)
	if !ok {
		return
	}
	prefix := r.URL.Query().Get("prefix")
	query := r.URL.Query().Get("q")
	continuationToken := r.URL.Query().Get("continuation_token")
	limit := h.parsePageLimit(r)

	page, err := h.browser.Search(r.Context(), os.ID, prefix, query, continuationToken, limit)
	if err != nil {
		writeObjectStorageBrowserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toObjectListPageDTO(page))
}

// GetObjectMetadata handles GET /api/object-storage/:id/objects/metadata.
func (h *ObjectStorageBrowserHandler) GetObjectMetadata(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageBrowser)
	if !ok {
		return
	}
	key := r.URL.Query().Get("key")
	md, err := h.browser.GetObjectMetadata(r.Context(), os.ID, key)
	if err != nil {
		writeObjectStorageBrowserError(w, err)
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditObjectStorageObjectViewed, ResourceType: "OBJECT_STORAGE", ResourceID: &os.ResourceID,
		Metadata: map[string]any{"key": key},
	})
	httpx.WriteJSON(w, http.StatusOK, objectMetadataDTO{
		Key: md.Key, SizeBytes: md.SizeBytes, ContentType: md.ContentType, ETag: md.ETag,
		LastModified: formatTimePtr(md.LastModified), StorageClass: md.StorageClass, Metadata: md.Metadata,
	})
}

// RequestDownload handles POST /api/object-storage/:id/objects/download.
// Requires object_storage.download ONLY -- not additionally
// object_storage.browser. This mirrors DatabaseBrowserHandler's own
// layering precedent exactly: GetLogs there requires database.logs alone
// (not database.browser too) even though logs are also a "browse-tier"
// concept, and EffectiveObjectStorageAccess/grantableObjectStoragePermissions
// (authorization.go/access.go) already treat object_storage.browser and
// object_storage.download as two independent, separately grantable
// permissions with no built-in hierarchy between them -- an Admin
// granting a Member ONLY object_storage.download (without .browser) is a
// legitimate, intentional grant this handler must honor, not silently
// upgrade into a two-permission requirement.
//
// Uses POST, not GET, per the plan's own explicit routing decision (and
// spec §48's wording: "this creates a stateful/sensitive short-lived
// token") -- see this file's package-level doc comment for the full
// GET-vs-POST reasoning and the resulting frontend-contract mismatch this
// diverges from.
func (h *ObjectStorageBrowserHandler) RequestDownload(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageDownload)
	if !ok {
		return
	}
	key := r.URL.Query().Get("key")
	url, expiresAt, err := h.browser.GeneratePresignedDownloadURL(r.Context(), os.ID, key, h.downloadURLTTL)
	if err != nil {
		writeObjectStorageBrowserError(w, err)
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	// Metadata carries only the key -- never the generated URL, which
	// embeds a temporary credential in its query string and is exactly as
	// sensitive as a raw secret for audit-log purposes (audit.go's own
	// documented rule).
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditObjectStorageObjectDownloaded, ResourceType: "OBJECT_STORAGE", ResourceID: &os.ResourceID,
		Metadata: map[string]any{"key": key},
	})
	httpx.WriteJSON(w, http.StatusOK, objectDownloadDTO{URL: url, ExpiresAt: expiresAt.Format(time.RFC3339)})
}

// GetPreview handles GET /api/object-storage/:id/objects/preview. Requires
// object_storage.browser (not .download) -- a preview never hands the
// caller the raw file or a way to retrieve it directly, only an inline,
// byte-capped, text/JSON-only rendering, matching the plan's own framing
// of preview as a browse-tier action.
func (h *ObjectStorageBrowserHandler) GetPreview(w http.ResponseWriter, r *http.Request) {
	os, ok := h.authorizeObjectStorage(w, r, services.PermObjectStorageBrowser)
	if !ok {
		return
	}
	key := r.URL.Query().Get("key")
	preview, err := h.browser.GetPreview(r.Context(), os.ID, key, h.previewMaxBytes)
	if err != nil {
		writeObjectStorageBrowserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, objectPreviewDTO{
		ContentType: preview.ContentType, Encoding: preview.Encoding, Content: preview.Content, Truncated: preview.Truncated,
	})
}
