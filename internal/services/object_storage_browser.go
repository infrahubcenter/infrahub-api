package services

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// This file implements Step 17 Phase 4's read-only object browser: prefix/
// pseudo-folder listing, prefix-anchored search, object metadata, a
// short-lived presigned download URL, and a byte-capped text/JSON preview.
// Mirrors the standalone-database browser's shape (database_browser.go /
// database_browser_service.go) as closely as the two domains allow -- the
// biggest divergence is validation: S3 keys can contain almost any UTF-8
// character (including "/" as an ordinary part of the key), so there is no
// SQL-identifier-style character whitelist here, only a path-traversal
// check (see isValidObjectPath). Every S3 call this file makes is
// ListObjectsV2, HeadObject, or GetObject (via presign or the bounded
// preview read) -- no write/delete/upload call exists anywhere in this
// feature, matching the plan's hard boundary for this phase.

// DefaultObjectPageSize/MaxObjectPageSize mirror
// DefaultBrowserRowLimit/MaxBrowserRowLimit's constant-with-handler-side-
// clamp pattern for the standalone database browser. MaxObjectPageSize is
// this package's compile-time absolute ceiling -- the handler additionally
// clamps against the config-overridable OBJECT_STORAGE_MAX_PAGE_SIZE
// before ever calling in here, but ListObjects/Search re-clamp against
// this constant unconditionally too, so a caller can never coax more than
// MaxObjectPageSize keys out of a single request no matter what the
// handler-side configuration says.
const (
	DefaultObjectPageSize = 50
	MaxObjectPageSize     = 200
)

// objectStorageBrowserCallTimeout bounds every individual S3 call this
// file makes. Unlike the fast/deep metrics cycles (which thread an
// explicit ConnectTimeout/CommandTimeout through ObjectStorageConnection
// because they run on a fixed background schedule with their own strict
// timeout budget), every browser call here is directly driven by an
// inbound HTTP request, so the request's own context is the primary
// cancellation signal -- this constant is only a defensive backstop
// against a single S3 call hanging indefinitely and leaking the request
// goroutine past the point any client is still waiting on it.
const objectStorageBrowserCallTimeout = 30 * time.Second

// Typed browser errors -- the handler classifies on these into HTTP
// statuses, never surfacing the raw AWS SDK error message (which can embed
// endpoint/query detail) to a caller.
var (
	// ErrObjectStorageInvalidPath is returned for a prefix/key that fails
	// isValidObjectPath -- a malformed-request problem (400), never an
	// IDOR-relevant existence question, so it must never be laundered into
	// authorizeObjectStorage's 404-not-403 discipline.
	ErrObjectStorageInvalidPath = errors.New("invalid object storage path")
	// ErrObjectStoragePreviewTooLarge means the object's real size (from a
	// HeadObject the preview path always runs first) exceeds the
	// configured OBJECT_STORAGE_PREVIEW_MAX_BYTES -- GetPreview returns
	// this WITHOUT ever issuing the GetObject call.
	ErrObjectStoragePreviewTooLarge = errors.New("object too large to preview")
	// ErrObjectStoragePreviewUnsupported means the object's Content-Type
	// isn't text-like or JSON -- GetPreview returns this without ever
	// attempting to read the body as text.
	ErrObjectStoragePreviewUnsupported = errors.New("preview not supported for this content type")
)

// ObjectEntryType is one listing entry's kind -- a pseudo-folder (an S3
// CommonPrefix) or a real object (an S3 Contents item).
type ObjectEntryType string

const (
	ObjectEntryFolder ObjectEntryType = "FOLDER"
	ObjectEntryObject ObjectEntryType = "OBJECT"
)

// ObjectEntry is one row of a ListObjects/Search page. Key is always
// relative to the storage's configured base_path (base_path is stripped
// before this is ever built -- see stripBasePath) and, for a FOLDER entry,
// is exactly the pseudo-folder prefix a caller would pass back as the next
// request's `prefix` to descend into it. SizeBytes/LastModified/
// StorageClass are only ever set for an OBJECT entry.
type ObjectEntry struct {
	Type         ObjectEntryType
	Name         string
	Key          string
	SizeBytes    *int64
	LastModified *time.Time
	StorageClass string
}

// ObjectListPage is ListObjects/Search's result shape -- Prefix always
// echoes the request's own (base_path-relative) prefix, never an
// internal, base_path-qualified one. NextContinuationToken is empty when
// there is no further page; pagination is cursor-based only, mirroring the
// plan's explicit "never offset-based" requirement.
type ObjectListPage struct {
	Bucket                string
	Prefix                string
	Entries               []ObjectEntry
	NextContinuationToken string
}

// ObjectMetadata is GetObjectMetadata's result shape -- Metadata carries
// only the object's user-defined x-amz-meta-* headers as the AWS SDK
// itself returns them, never fabricated.
type ObjectMetadata struct {
	Key          string
	SizeBytes    int64
	ContentType  string
	ETag         string
	LastModified *time.Time
	StorageClass string
	Metadata     map[string]string
}

// ObjectPreview is GetPreview's result shape. Encoding is "utf-8" when the
// (possibly truncated) byte range read back valid UTF-8 text, else
// "base64" -- the wire contract never emits invalid-UTF-8 raw bytes as a
// JSON string. Truncated is true whenever the object's real size exceeds
// how much of it was actually read.
type ObjectPreview struct {
	ContentType string
	Encoding    string
	Content     string
	Truncated   bool
}

// ObjectStorageBrowserService implements the read-only object browser
// against a standalone object storage's live bucket. Every method
// resolves storageID to its stored connection details + decrypted
// credential itself (rather than requiring the caller to have already
// loaded the generated.ObjectStorage row) so it stays independently
// testable and usable outside the HTTP handler layer.
type ObjectStorageBrowserService struct {
	store       *repository.Store
	credentials *StandaloneObjectStorageCredentialService
}

// NewObjectStorageBrowserService creates an ObjectStorageBrowserService.
func NewObjectStorageBrowserService(store *repository.Store, credentials *StandaloneObjectStorageCredentialService) *ObjectStorageBrowserService {
	return &ObjectStorageBrowserService{store: store, credentials: credentials}
}

// isValidObjectPath reports whether p is safe to use as a browsing prefix,
// search fragment, or object key. Deliberately NOT a SQL-identifier-style
// character whitelist (isValidIdentifier, database_browser.go's
// equivalent) -- an S3 key can legitimately contain almost any UTF-8
// character, "/" included, as an ordinary part of the key. The only
// concern here is a path-traversal-style attempt to escape the storage's
// configured base_path: a literal ".." path segment, or a leading "/"
// that would otherwise be (mis)treated as bucket-root-absolute instead of
// relative to base_path. An empty string is valid (it means "the storage's
// own root").
func isValidObjectPath(p string) bool {
	if strings.HasPrefix(p, "/") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// clampObjectPageSize enforces this package's hard ceiling regardless of
// what the caller (handler, already itself clamped against the
// config-driven OBJECT_STORAGE_MAX_PAGE_SIZE) asked for -- defense in
// depth, per the plan's "respect MaxObjectPageSize server-side regardless
// of what the client requests" requirement.
func clampObjectPageSize(limit int) int32 {
	if limit <= 0 {
		limit = DefaultObjectPageSize
	}
	if limit > MaxObjectPageSize {
		limit = MaxObjectPageSize
	}
	return int32(limit)
}

// normalizeBasePath strips any leading/trailing "/" a stored base_path
// might carry, so joinBasePath/stripBasePath never have to worry about
// double slashes.
func normalizeBasePath(basePath string) string {
	return strings.Trim(basePath, "/")
}

// joinBasePath prepends the storage's configured base_path onto a
// caller-supplied, already-validated (isValidObjectPath) relative
// prefix/key -- the ONLY place this feature ever builds the real S3 path
// it sends on the wire. Every request is confined to this subtree even if
// the underlying credential's IAM/bucket policy technically allows
// broader access.
func joinBasePath(basePath, rel string) string {
	bp := normalizeBasePath(basePath)
	if bp == "" {
		return rel
	}
	if rel == "" {
		return bp + "/"
	}
	return bp + "/" + rel
}

// stripBasePath removes the storage's configured base_path prefix from a
// full S3 key/prefix before it is EVER returned to a caller -- base_path
// is a purely internal, per-instance configuration detail the frontend/UI
// must never see or need to know about. Every full key this is called
// with was itself derived by joinBasePath and sent to S3 as the Prefix of
// the very same request, so S3's own Prefix-filtering contract (every
// returned key/CommonPrefix genuinely starts with the requested Prefix)
// means TrimPrefix below always actually matches in practice -- it is
// written as a plain TrimPrefix (a no-op, never a leak, if the prefix
// somehow didn't match) rather than a branch that could fall back to
// returning the untrimmed, base_path-containing string.
func stripBasePath(basePath, full string) string {
	bp := normalizeBasePath(basePath)
	if bp == "" {
		return full
	}
	return strings.TrimPrefix(full, bp+"/")
}

// isFolderMarkerObject reports whether key is the exact-prefix-match
// placeholder object some tools create (a zero-byte object whose key
// equals a pseudo-folder path, e.g. "docs/") -- excluded from ListObjects/
// Search's OBJECT entries the same way most S3 browsers hide it, since it
// carries no real content and duplicates the FOLDER entry the same
// request already produces via CommonPrefixes.
func isFolderMarkerObject(key, fullPrefix string) bool {
	return key == fullPrefix && (fullPrefix == "" || strings.HasSuffix(fullPrefix, "/"))
}

// isPreviewableContentType is GetPreview's conservative text/JSON gate:
// any text/* type, plus a short, deliberately narrow list of common
// textual application/* types. Everything else (including an empty/
// unknown Content-Type, which many providers default to
// application/octet-stream for) is treated as NOT previewable -- "we
// don't know" must never be guessed into "probably text."
func isPreviewableContentType(contentType string) bool {
	ct := contentType
	if idx := strings.Index(ct, ";"); idx >= 0 {
		ct = ct[:idx]
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	switch ct {
	case "application/json", "application/xml", "application/javascript", "application/x-ndjson":
		return true
	default:
		return false
	}
}

// loadClient resolves storageID to a live S3 client plus the row's
// base_path -- the single shared connection-building helper every method
// below uses, so newS3Client's construction (and the credential decrypt
// that feeds it) is never duplicated per-method. Mirrors the exact
// ObjectStorageConnection field mapping ObjectStorageMetricsService/
// ObjectStorageDeepMetricsService use.
func (s *ObjectStorageBrowserService) loadClient(ctx context.Context, storageID uuid.UUID) (client *s3.Client, row generated.ObjectStorage, basePath string, err error) {
	row, err = s.store.GetObjectStorageByID(ctx, storageID)
	if err != nil || row.DeletedAt.Valid {
		// Should be unreachable in practice -- every caller already ran
		// authorizeObjectStorage (existence + soft-delete check) before
		// reaching here. Classified the same as any other "not found"
		// outcome (a race where the storage was deleted between that check
		// and this call) rather than introducing a second, parallel
		// not-found error type.
		return nil, generated.ObjectStorage{}, "", fmt.Errorf("%w: object storage no longer exists", ErrObjectStorageNotFound)
	}
	secretAccessKey, err := s.credentials.GetSecretKey(ctx, storageID)
	if err != nil {
		return nil, generated.ObjectStorage{}, "", fmt.Errorf("%w: no credential configured", ErrObjectStorageAuth)
	}
	conn := ObjectStorageConnection{
		Provider: row.Provider, Endpoint: pgutil.TextOrEmpty(row.Endpoint), Region: pgutil.TextOrEmpty(row.Region),
		Bucket: row.Bucket, BasePath: pgutil.TextOrEmpty(row.BasePath), AccessKeyID: pgutil.TextOrEmpty(row.AccessKeyID),
		SecretAccessKey: secretAccessKey, TLSEnabled: row.TlsEnabled, TLSSkipVerify: row.TlsSkipVerify,
	}
	client, err = newS3Client(conn)
	if err != nil {
		return nil, generated.ObjectStorage{}, "", fmt.Errorf("%w: %v", ErrObjectStorageConnection, err)
	}
	return client, row, pgutil.TextOrEmpty(row.BasePath), nil
}

// buildEntries maps one ListObjectsV2 response's CommonPrefixes/Contents
// into base_path-relative ObjectEntry rows -- shared by ListObjects and
// Search so the two never drift in how they build/skip/name entries.
func buildEntries(basePath, fullPrefix string, commonPrefixes []string, contents []s3ObjectSummary) []ObjectEntry {
	entries := make([]ObjectEntry, 0, len(commonPrefixes)+len(contents))
	for _, full := range commonPrefixes {
		rel := stripBasePath(basePath, full)
		entries = append(entries, ObjectEntry{Type: ObjectEntryFolder, Name: path.Base(rel), Key: rel})
	}
	for _, obj := range contents {
		if isFolderMarkerObject(obj.Key, fullPrefix) {
			continue
		}
		rel := stripBasePath(basePath, obj.Key)
		entry := ObjectEntry{Type: ObjectEntryObject, Name: path.Base(rel), Key: rel, StorageClass: obj.StorageClass}
		if obj.Size != nil {
			entry.SizeBytes = obj.Size
		}
		if obj.LastModified != nil {
			entry.LastModified = obj.LastModified
		}
		entries = append(entries, entry)
	}
	return entries
}

// s3ObjectSummary is a tiny provider-agnostic shim over s3types.Object so
// buildEntries doesn't need to import the types package just to spell out
// its field types.
type s3ObjectSummary struct {
	Key          string
	Size         *int64
	LastModified *time.Time
	StorageClass string
}

// listOnePage runs one ListObjectsV2 call and returns the raw response
// pieces ListObjects/Search each turn into an ObjectListPage -- shared so
// the two never diverge in request construction.
func (s *ObjectStorageBrowserService) listOnePage(ctx context.Context, client *s3.Client, bucket, fullPrefix, continuationToken string, limit int) (commonPrefixes []string, contents []s3ObjectSummary, nextToken string, err error) {
	cctx, cancel := context.WithTimeout(ctx, objectStorageBrowserCallTimeout)
	defer cancel()
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket), Prefix: aws.String(fullPrefix), Delimiter: aws.String("/"),
		MaxKeys: aws.Int32(clampObjectPageSize(limit)),
	}
	if continuationToken != "" {
		input.ContinuationToken = aws.String(continuationToken)
	}
	out, err := client.ListObjectsV2(cctx, input)
	if err != nil {
		return nil, nil, "", classifyObjectStorageError(err)
	}
	for _, cp := range out.CommonPrefixes {
		commonPrefixes = append(commonPrefixes, aws.ToString(cp.Prefix))
	}
	for _, obj := range out.Contents {
		contents = append(contents, s3ObjectSummary{
			Key: aws.ToString(obj.Key), Size: obj.Size, LastModified: obj.LastModified, StorageClass: string(obj.StorageClass),
		})
	}
	if out.IsTruncated != nil && *out.IsTruncated && out.NextContinuationToken != nil {
		nextToken = *out.NextContinuationToken
	}
	return commonPrefixes, contents, nextToken, nil
}

// ListObjects lists one page of a bucket's pseudo-folder/object listing
// under prefix (relative to the storage's configured base_path).
// Delimiter="/" groups everything one level deeper into CommonPrefixes
// (FOLDER entries) rather than flattening the whole subtree, and
// ContinuationToken/MaxKeys drive cursor-based (never offset-based)
// pagination, exactly per plan.
func (s *ObjectStorageBrowserService) ListObjects(ctx context.Context, storageID uuid.UUID, prefix, continuationToken string, limit int) (ObjectListPage, error) {
	if !isValidObjectPath(prefix) {
		return ObjectListPage{}, ErrObjectStorageInvalidPath
	}
	client, row, basePath, err := s.loadClient(ctx, storageID)
	if err != nil {
		return ObjectListPage{}, err
	}
	fullPrefix := joinBasePath(basePath, prefix)

	commonPrefixes, contents, nextToken, err := s.listOnePage(ctx, client, row.Bucket, fullPrefix, continuationToken, limit)
	if err != nil {
		return ObjectListPage{}, err
	}
	return ObjectListPage{
		Bucket: row.Bucket, Prefix: prefix, Entries: buildEntries(basePath, fullPrefix, commonPrefixes, contents),
		NextContinuationToken: nextToken,
	}, nil
}

// objectStoragePrefixSizeMaxPages bounds GetPrefixSize's recursive walk --
// mirrors object_storage_deep_metrics_collect.go's
// objectStorageDeepListMaxPages exactly (same "no unbounded bucket scans,
// ever" constraint), just scoped to one folder's subtree instead of the
// whole bucket. At up to 1,000 keys/page that's still a 20,000-key ceiling
// per folder, regardless of how deep or wide it actually is.
const objectStoragePrefixSizeMaxPages = 20

// PrefixSizeResult is GetPrefixSize's result -- a real but possibly
// incomplete aggregate, never silently presented as exact once Truncated
// is true.
type PrefixSizeResult struct {
	ObjectCount    int64
	TotalSizeBytes int64
	Truncated      bool
}

// GetPrefixSize recursively sums every object's size under prefix (relative
// to base_path) -- S3 has no native "folder size" API, so this is a
// client-side ListObjectsV2 walk with NO Delimiter (unlike ListObjects
// above, which groups one level at a time): every key anywhere under the
// prefix counts, nested subfolders included. Bounded at
// objectStoragePrefixSizeMaxPages pages; hitting that cap sets Truncated so
// callers/UI never present a partial sum as the folder's true total.
func (s *ObjectStorageBrowserService) GetPrefixSize(ctx context.Context, storageID uuid.UUID, prefix string) (PrefixSizeResult, error) {
	if !isValidObjectPath(prefix) {
		return PrefixSizeResult{}, ErrObjectStorageInvalidPath
	}
	client, row, basePath, err := s.loadClient(ctx, storageID)
	if err != nil {
		return PrefixSizeResult{}, err
	}
	fullPrefix := joinBasePath(basePath, prefix)

	var result PrefixSizeResult
	var token *string
	for page := 0; page < objectStoragePrefixSizeMaxPages; page++ {
		cctx, cancel := context.WithTimeout(ctx, objectStorageBrowserCallTimeout)
		out, err := client.ListObjectsV2(cctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(row.Bucket), Prefix: aws.String(fullPrefix), ContinuationToken: token,
		})
		cancel()
		if err != nil {
			return PrefixSizeResult{}, classifyObjectStorageError(err)
		}
		for _, obj := range out.Contents {
			result.ObjectCount++
			if obj.Size != nil {
				result.TotalSizeBytes += *obj.Size
			}
		}
		if out.IsTruncated == nil || !*out.IsTruncated || out.NextContinuationToken == nil {
			return result, nil
		}
		token = out.NextContinuationToken
	}
	result.Truncated = true
	return result, nil
}

// Search lists one page of keys starting with prefix+query (relative to
// base_path) -- pure prefix concatenation, no wildcard/regex language,
// exactly per plan. Chose to KEEP Delimiter="/" grouping here (rather than
// a fully flattened match list): it keeps Search's response shape and
// folder-grouping behavior identical to ListObjects, matching this
// feature's "prefix + pseudo-folder" navigation model -- since real
// wildcard/substring search is explicitly out of scope, a search is really
// just "list, but anchored at a longer, partially-typed prefix," and the
// frontend can render its result with the exact same table/tree component
// it already uses for ListObjects instead of a second, deep flat-listing
// mode.
func (s *ObjectStorageBrowserService) Search(ctx context.Context, storageID uuid.UUID, prefix, query, continuationToken string, limit int) (ObjectListPage, error) {
	if !isValidObjectPath(prefix) || !isValidObjectPath(query) {
		return ObjectListPage{}, ErrObjectStorageInvalidPath
	}
	client, row, basePath, err := s.loadClient(ctx, storageID)
	if err != nil {
		return ObjectListPage{}, err
	}
	fullPrefix := joinBasePath(basePath, prefix) + query

	commonPrefixes, contents, nextToken, err := s.listOnePage(ctx, client, row.Bucket, fullPrefix, continuationToken, limit)
	if err != nil {
		return ObjectListPage{}, err
	}
	return ObjectListPage{
		Bucket: row.Bucket, Prefix: prefix, Entries: buildEntries(basePath, fullPrefix, commonPrefixes, contents),
		NextContinuationToken: nextToken,
	}, nil
}

// GetObjectMetadata runs one HeadObject call for key (relative to
// base_path) and returns its size/content-type/etag/last-modified/
// storage-class/user-metadata -- only what the SDK actually returns, never
// fabricated.
func (s *ObjectStorageBrowserService) GetObjectMetadata(ctx context.Context, storageID uuid.UUID, key string) (ObjectMetadata, error) {
	if key == "" || !isValidObjectPath(key) {
		return ObjectMetadata{}, ErrObjectStorageInvalidPath
	}
	client, row, basePath, err := s.loadClient(ctx, storageID)
	if err != nil {
		return ObjectMetadata{}, err
	}
	fullKey := joinBasePath(basePath, key)

	cctx, cancel := context.WithTimeout(ctx, objectStorageBrowserCallTimeout)
	defer cancel()
	out, err := client.HeadObject(cctx, &s3.HeadObjectInput{Bucket: aws.String(row.Bucket), Key: aws.String(fullKey)})
	if err != nil {
		return ObjectMetadata{}, classifyObjectStorageError(err)
	}
	md := ObjectMetadata{
		Key: key, ContentType: aws.ToString(out.ContentType), ETag: aws.ToString(out.ETag),
		StorageClass: string(out.StorageClass), LastModified: out.LastModified, Metadata: out.Metadata,
	}
	if out.ContentLength != nil {
		md.SizeBytes = *out.ContentLength
	}
	if md.Metadata == nil {
		md.Metadata = map[string]string{}
	}
	return md, nil
}

// GeneratePresignedDownloadURL returns a short-lived presigned GET URL for
// key (relative to base_path), valid for ttl. Presigning is a pure, local,
// side-effect-free computation (no server-side state is created; the URL
// itself is self-contained) -- it does not confirm the object exists
// first via HeadObject: an extra existence check would be a needless round
// trip that is racy anyway (the object could be removed between the check
// and the URL actually being used), and real S3 behavior for a presigned
// URL against a missing key is already the right answer -- fetching it
// simply 404s, exactly like fetching any other missing-key URL would.
func (s *ObjectStorageBrowserService) GeneratePresignedDownloadURL(ctx context.Context, storageID uuid.UUID, key string, ttl time.Duration) (string, time.Time, error) {
	if key == "" || !isValidObjectPath(key) {
		return "", time.Time{}, ErrObjectStorageInvalidPath
	}
	client, row, basePath, err := s.loadClient(ctx, storageID)
	if err != nil {
		return "", time.Time{}, err
	}
	fullKey := joinBasePath(basePath, key)

	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	presignClient := s3.NewPresignClient(client)
	pctx, cancel := context.WithTimeout(ctx, objectStorageBrowserCallTimeout)
	defer cancel()
	req, err := presignClient.PresignGetObject(pctx, &s3.GetObjectInput{Bucket: aws.String(row.Bucket), Key: aws.String(fullKey)}, s3.WithPresignExpires(ttl))
	if err != nil {
		return "", time.Time{}, classifyObjectStorageError(err)
	}
	return req.URL, time.Now().Add(ttl), nil
}

// GetPreview returns a byte-capped text/JSON preview of key (relative to
// base_path). Always runs HeadObject first: if the object's real size
// exceeds maxBytes, this returns ErrObjectStoragePreviewTooLarge WITHOUT
// ever issuing the GetObject call below; if the Content-Type isn't
// text-like/JSON (isPreviewableContentType), this returns
// ErrObjectStoragePreviewUnsupported, also without attempting to read the
// body. Only once both gates pass does it GetObject with an explicit
// Range header capping the request to maxBytes -- and even then never
// trusts the server to honor Range exactly, enforcing a hard second cap
// via io.LimitReader on the response body itself.
func (s *ObjectStorageBrowserService) GetPreview(ctx context.Context, storageID uuid.UUID, key string, maxBytes int64) (ObjectPreview, error) {
	if key == "" || !isValidObjectPath(key) {
		return ObjectPreview{}, ErrObjectStorageInvalidPath
	}
	if maxBytes <= 0 {
		maxBytes = 5 * 1024 * 1024 // defensive fallback; the handler always passes the configured OBJECT_STORAGE_PREVIEW_MAX_BYTES.
	}
	client, row, basePath, err := s.loadClient(ctx, storageID)
	if err != nil {
		return ObjectPreview{}, err
	}
	fullKey := joinBasePath(basePath, key)

	hctx, hcancel := context.WithTimeout(ctx, objectStorageBrowserCallTimeout)
	head, err := client.HeadObject(hctx, &s3.HeadObjectInput{Bucket: aws.String(row.Bucket), Key: aws.String(fullKey)})
	hcancel()
	if err != nil {
		return ObjectPreview{}, classifyObjectStorageError(err)
	}

	var size int64
	if head.ContentLength != nil {
		size = *head.ContentLength
	}
	if size > maxBytes {
		return ObjectPreview{}, ErrObjectStoragePreviewTooLarge
	}
	contentType := aws.ToString(head.ContentType)
	if !isPreviewableContentType(contentType) {
		return ObjectPreview{}, ErrObjectStoragePreviewUnsupported
	}

	gctx, gcancel := context.WithTimeout(ctx, objectStorageBrowserCallTimeout)
	defer gcancel()
	out, err := client.GetObject(gctx, &s3.GetObjectInput{
		Bucket: aws.String(row.Bucket), Key: aws.String(fullKey), Range: aws.String(fmt.Sprintf("bytes=0-%d", maxBytes-1)),
	})
	if err != nil {
		return ObjectPreview{}, classifyObjectStorageError(err)
	}
	defer out.Body.Close()

	data, err := io.ReadAll(io.LimitReader(out.Body, maxBytes))
	if err != nil {
		return ObjectPreview{}, fmt.Errorf("read object preview body: %w", err)
	}

	// Prefer the GetObject response's own Content-Range total ("bytes
	// 0-N/TOTAL") over the earlier HeadObject snapshot when present -- more
	// authoritative/fresher, and correctly detects truncation in the rare
	// case the object grew between the HeadObject and GetObject calls
	// (HeadObject's size alone would otherwise under-report it).
	totalSize := size
	if cr := aws.ToString(out.ContentRange); cr != "" {
		if idx := strings.LastIndex(cr, "/"); idx >= 0 {
			if v, err := strconv.ParseInt(cr[idx+1:], 10, 64); err == nil {
				totalSize = v
			}
		}
	}
	preview := ObjectPreview{ContentType: contentType, Truncated: totalSize > int64(len(data))}
	if utf8.Valid(data) {
		preview.Encoding = "utf-8"
		preview.Content = string(data)
	} else {
		preview.Encoding = "base64"
		preview.Content = base64.StdEncoding.EncodeToString(data)
	}
	return preview, nil
}
