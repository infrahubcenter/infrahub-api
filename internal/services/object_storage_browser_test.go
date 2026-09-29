package services

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database"
	"vmcontrolcenter/backend/internal/repository"
)

// This file exercises ObjectStorageBrowserService (Step 17 Phase 4)
// directly, bypassing the HTTP layer entirely -- IDOR/permission-tier
// checks live in the handler (see internal/server's object storage tests)
// and belong there; this file's job is the browsing/pagination/validation/
// preview LOGIC itself: path-traversal rejection, pagination round-trips,
// folder-grouping, base_path scoping enforced server-side (not cosmetic),
// object metadata mapping, presigned URL shape, and preview size/
// content-type gating. Every S3 call is against an in-process httptest
// fake server, per this project's established decision #10 pattern
// (object_storage_adapter_test.go / object_storage_deep_metrics_collect_test.go).

// --- pure, DB-independent unit tests ---

func TestIsValidObjectPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"", true},
		{"docs/report.pdf", true},
		{"a/b/c", true},
		{"docs/", true},
		{"/etc/passwd", false},
		{"../etc/passwd", false},
		{"docs/../secret", false},
		{"docs/..", false},
		{"..", false},
		{"...", true}, // three dots is not the special ".." segment
	}
	for _, c := range cases {
		if got := isValidObjectPath(c.path); got != c.want {
			t.Errorf("isValidObjectPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestJoinAndStripBasePath(t *testing.T) {
	joinCases := []struct{ basePath, rel, want string }{
		{"", "docs/x", "docs/x"},
		{"", "", ""},
		{"tenant-a", "", "tenant-a/"},
		{"tenant-a", "docs/x", "tenant-a/docs/x"},
		{"/tenant-a/", "docs/x", "tenant-a/docs/x"}, // leading/trailing slashes normalized away
	}
	for _, c := range joinCases {
		if got := joinBasePath(c.basePath, c.rel); got != c.want {
			t.Errorf("joinBasePath(%q, %q) = %q, want %q", c.basePath, c.rel, got, c.want)
		}
	}

	stripCases := []struct{ basePath, full, want string }{
		{"", "docs/x", "docs/x"},
		{"tenant-a", "tenant-a/docs/x", "docs/x"},
		{"tenant-a", "tenant-a/", ""},
	}
	for _, c := range stripCases {
		if got := stripBasePath(c.basePath, c.full); got != c.want {
			t.Errorf("stripBasePath(%q, %q) = %q, want %q", c.basePath, c.full, got, c.want)
		}
	}
}

func TestIsPreviewableContentType(t *testing.T) {
	previewable := []string{"text/plain", "text/plain; charset=utf-8", "TEXT/CSV", "application/json", "APPLICATION/JSON", "application/xml", "application/javascript"}
	for _, ct := range previewable {
		if !isPreviewableContentType(ct) {
			t.Errorf("isPreviewableContentType(%q) = false, want true", ct)
		}
	}
	notPreviewable := []string{"", "image/png", "application/octet-stream", "application/pdf", "video/mp4", "application/zip"}
	for _, ct := range notPreviewable {
		if isPreviewableContentType(ct) {
			t.Errorf("isPreviewableContentType(%q) = true, want false", ct)
		}
	}
}

// TestObjectStorageBrowserPathTraversalRejected_NeverTouchesStore uses a
// zero-value service (nil store/credentials) -- proving every method
// validates its prefix/key BEFORE ever attempting to load a connection
// (which would otherwise nil-panic on store.GetObjectStorageByID). This is
// the plan's explicit "validate before ever constructing an S3 API call,
// not just cosmetically in the response" requirement, verified for every
// entry point.
func TestObjectStorageBrowserPathTraversalRejected_NeverTouchesStore(t *testing.T) {
	svc := NewObjectStorageBrowserService(nil, nil)
	ctx := context.Background()
	fakeID := uuid.New()

	if _, err := svc.ListObjects(ctx, fakeID, "../etc", "", 10); !errors.Is(err, ErrObjectStorageInvalidPath) {
		t.Errorf("ListObjects(../etc): err = %v, want ErrObjectStorageInvalidPath", err)
	}
	if _, err := svc.ListObjects(ctx, fakeID, "/etc", "", 10); !errors.Is(err, ErrObjectStorageInvalidPath) {
		t.Errorf("ListObjects(/etc): err = %v, want ErrObjectStorageInvalidPath", err)
	}
	if _, err := svc.Search(ctx, fakeID, "", "../secret", "", 10); !errors.Is(err, ErrObjectStorageInvalidPath) {
		t.Errorf("Search(query=../secret): err = %v, want ErrObjectStorageInvalidPath", err)
	}
	if _, err := svc.Search(ctx, fakeID, "../etc", "x", "", 10); !errors.Is(err, ErrObjectStorageInvalidPath) {
		t.Errorf("Search(prefix=../etc): err = %v, want ErrObjectStorageInvalidPath", err)
	}
	if _, err := svc.GetObjectMetadata(ctx, fakeID, "../secret"); !errors.Is(err, ErrObjectStorageInvalidPath) {
		t.Errorf("GetObjectMetadata(../secret): err = %v, want ErrObjectStorageInvalidPath", err)
	}
	if _, _, err := svc.GeneratePresignedDownloadURL(ctx, fakeID, "../secret", time.Minute); !errors.Is(err, ErrObjectStorageInvalidPath) {
		t.Errorf("GeneratePresignedDownloadURL(../secret): err = %v, want ErrObjectStorageInvalidPath", err)
	}
	if _, err := svc.GetPreview(ctx, fakeID, "../secret", 1024); !errors.Is(err, ErrObjectStorageInvalidPath) {
		t.Errorf("GetPreview(../secret): err = %v, want ErrObjectStorageInvalidPath", err)
	}
}

// --- DB-backed tests (real Postgres, fake S3 over httptest) ---

// setupObjectStorageBrowserDB connects to a real local Postgres (this
// project's "real Postgres, not a mock" precedent, same as
// authorization_test.go) and returns a ready-to-use
// ObjectStorageBrowserService, the domain service used to seed a storage
// fixture, and a fresh project ID fixtures can attach to. Skips (not
// fails) when DATABASE_URL is unset.
func setupObjectStorageBrowserDB(t *testing.T) (*ObjectStorageBrowserService, *ObjectStorageService, uuid.UUID) {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL not set; skipping object storage browser DB-backed test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := database.NewPool(ctx, databaseURL, database.PoolConfig{MaxConns: 5, MinConns: 1, ConnectTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("connect to database: %v", err)
	}
	t.Cleanup(pool.Close)
	store := repository.New(pool)

	encryptionKey, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("generate encryption key: %v", err)
	}
	encryption, err := NewEncryptionService(encryptionKey)
	if err != nil {
		t.Fatalf("build encryption service: %v", err)
	}
	credentialSvc := NewStandaloneObjectStorageCredentialService(store, encryption)
	domainSvc := NewObjectStorageService(store, credentialSvc)
	browserSvc := NewObjectStorageBrowserService(store, credentialSvc)

	workspaceSvc := NewWorkspaceService(store)
	workspace, err := workspaceSvc.Create(ctx, "browser-test-"+uuid.NewString(), "")
	if err != nil {
		t.Fatalf("create test workspace: %v", err)
	}
	return browserSvc, domainSvc, workspace.ID
}

// createBrowserStorageFixture registers a standalone object storage
// pointed at endpoint (a local httptest fake-S3 server, or an unreachable
// fake host for tests -- like presign generation -- that never dial out)
// with the given base_path, directly through ObjectStorageService
// (bypassing HTTP), mirroring server_test's createObjectStorageFixture
// shape.
func createBrowserStorageFixture(t *testing.T, domainSvc *ObjectStorageService, projectID uuid.UUID, endpoint, basePath string) uuid.UUID {
	t.Helper()
	row, err := domainSvc.Configure(context.Background(), ConfigureObjectStorageInput{
		WorkspaceID: projectID, Name: "browser-test-storage-" + uuid.NewString(), Provider: "S3_COMPATIBLE",
		Endpoint: endpoint, Region: "us-east-1", Bucket: "test-bucket", BasePath: basePath,
		AccessKeyID: "AKIAFAKE", SecretAccessKey: "fakesecret",
	})
	if err != nil {
		t.Fatalf("create browser storage fixture: %v", err)
	}
	return row.ID
}

// fakeBrowserHandlers/fakeBrowserServer route a fake-S3 httptest server on
// ListObjectsV2's query string (?list-type=2) vs plain HTTP method
// (HEAD -> HeadObject, GET -> GetObject) -- HeadObject/GetObject share the
// same URL shape on real S3 (the object's path), distinguished only by
// method, exactly like the real API.
type fakeBrowserHandlers struct {
	listObjects func(w http.ResponseWriter, r *http.Request)
	headObject  func(w http.ResponseWriter, r *http.Request)
	getObject   func(w http.ResponseWriter, r *http.Request)
}

func fakeBrowserServer(t *testing.T, h fakeBrowserHandlers) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Query().Has("list-type") && h.listObjects != nil:
			h.listObjects(w, r)
		case r.Method == http.MethodHead && h.headObject != nil:
			h.headObject(w, r)
		case r.Method == http.MethodGet && h.getObject != nil:
			h.getObject(w, r)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestObjectStorageBrowserListObjects_PaginationRoundTrip(t *testing.T) {
	browserSvc, domainSvc, projectID := setupObjectStorageBrowserDB(t)

	var calls int32
	srv := fakeBrowserServer(t, fakeBrowserHandlers{
		listObjects: func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&calls, 1)
			if n == 1 {
				if got := r.URL.Query().Get("continuation-token"); got != "" {
					t.Errorf("first ListObjectsV2 call should carry no continuation token, got %q", got)
				}
				xmlOK(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
					<Name>test-bucket</Name><IsTruncated>true</IsTruncated><NextContinuationToken>tok1</NextContinuationToken>
					<Contents><Key>a.txt</Key><Size>10</Size></Contents>
					<Contents><Key>b.txt</Key><Size>20</Size></Contents>
				</ListBucketResult>`)
				return
			}
			if got := r.URL.Query().Get("continuation-token"); got != "tok1" {
				t.Errorf("second ListObjectsV2 call continuation-token = %q, want tok1", got)
			}
			xmlOK(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
				<Name>test-bucket</Name><IsTruncated>false</IsTruncated>
				<Contents><Key>c.txt</Key><Size>30</Size></Contents>
			</ListBucketResult>`)
		},
	})
	storageID := createBrowserStorageFixture(t, domainSvc, projectID, srv.URL, "")

	page1, err := browserSvc.ListObjects(context.Background(), storageID, "", "", 50)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Entries) != 2 {
		t.Fatalf("page1 entries = %+v, want 2", page1.Entries)
	}
	if page1.NextContinuationToken != "tok1" {
		t.Fatalf("page1 next token = %q, want tok1", page1.NextContinuationToken)
	}

	page2, err := browserSvc.ListObjects(context.Background(), storageID, "", page1.NextContinuationToken, 50)
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Entries) != 1 || page2.Entries[0].Key != "c.txt" {
		t.Fatalf("page2 entries = %+v, want [{Key: c.txt}]", page2.Entries)
	}
	if page2.NextContinuationToken != "" {
		t.Fatalf("page2 next token = %q, want empty (last page)", page2.NextContinuationToken)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("ListObjectsV2 calls = %d, want exactly 2", got)
	}
}

func TestObjectStorageBrowserListObjects_FolderGroupingAndMarkerExcluded(t *testing.T) {
	browserSvc, domainSvc, projectID := setupObjectStorageBrowserDB(t)

	srv := fakeBrowserServer(t, fakeBrowserHandlers{
		listObjects: func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("prefix"); got != "docs/" {
				t.Errorf("prefix sent to S3 = %q, want docs/", got)
			}
			if got := r.URL.Query().Get("delimiter"); got != "/" {
				t.Errorf("delimiter sent to S3 = %q, want /", got)
			}
			xmlOK(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
				<Name>test-bucket</Name><IsTruncated>false</IsTruncated>
				<Contents><Key>docs/</Key><Size>0</Size></Contents>
				<Contents><Key>docs/report.pdf</Key><Size>1024</Size><StorageClass>STANDARD</StorageClass></Contents>
				<CommonPrefixes><Prefix>docs/sub/</Prefix></CommonPrefixes>
			</ListBucketResult>`)
		},
	})
	storageID := createBrowserStorageFixture(t, domainSvc, projectID, srv.URL, "")

	page, err := browserSvc.ListObjects(context.Background(), storageID, "docs/", "", 50)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if len(page.Entries) != 2 {
		t.Fatalf("entries = %+v, want exactly 2 (the docs/ zero-byte folder marker must be excluded)", page.Entries)
	}
	var gotFolder, gotObject bool
	for _, e := range page.Entries {
		switch e.Type {
		case ObjectEntryFolder:
			gotFolder = true
			if e.Key != "docs/sub/" || e.Name != "sub" {
				t.Errorf("folder entry = %+v, want key=docs/sub/ name=sub", e)
			}
		case ObjectEntryObject:
			gotObject = true
			if e.Key != "docs/report.pdf" || e.Name != "report.pdf" || e.StorageClass != "STANDARD" {
				t.Errorf("object entry = %+v", e)
			}
			if e.SizeBytes == nil || *e.SizeBytes != 1024 {
				t.Errorf("object size = %v, want 1024", e.SizeBytes)
			}
		default:
			t.Errorf("unexpected entry type %q", e.Type)
		}
	}
	if !gotFolder || !gotObject {
		t.Fatalf("expected both a FOLDER and an OBJECT entry, got %+v", page.Entries)
	}
}

// TestObjectStorageBrowserListObjects_BasePathScopedServerSide confirms
// base_path scoping is enforced by actually prepending it onto the S3
// Prefix sent on the wire (never just cosmetically stripped from the
// response) and stripped back off every returned entry, so the frontend
// never sees or needs to know about it.
func TestObjectStorageBrowserListObjects_BasePathScopedServerSide(t *testing.T) {
	browserSvc, domainSvc, projectID := setupObjectStorageBrowserDB(t)

	srv := fakeBrowserServer(t, fakeBrowserHandlers{
		listObjects: func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("prefix"); got != "tenant-a/" {
				t.Errorf("prefix sent to S3 = %q, want tenant-a/ (base_path must be prepended server-side, not just documented)", got)
			}
			xmlOK(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
				<Name>test-bucket</Name><IsTruncated>false</IsTruncated>
				<Contents><Key>tenant-a/file.txt</Key><Size>5</Size></Contents>
			</ListBucketResult>`)
		},
	})
	storageID := createBrowserStorageFixture(t, domainSvc, projectID, srv.URL, "tenant-a")

	page, err := browserSvc.ListObjects(context.Background(), storageID, "", "", 50)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if len(page.Entries) != 1 || page.Entries[0].Key != "file.txt" {
		t.Fatalf("entries = %+v, want [{Key: file.txt}] (base_path must be stripped from the response)", page.Entries)
	}
	for _, e := range page.Entries {
		if strings.Contains(e.Key, "tenant-a") || strings.Contains(e.Name, "tenant-a") {
			t.Errorf("entry leaked base_path back to the caller: %+v", e)
		}
	}
}

func TestObjectStorageBrowserSearch_PrefixConcatenation(t *testing.T) {
	browserSvc, domainSvc, projectID := setupObjectStorageBrowserDB(t)

	srv := fakeBrowserServer(t, fakeBrowserHandlers{
		listObjects: func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("prefix"); got != "docs/rep" {
				t.Errorf("search prefix sent to S3 = %q, want docs/rep (pure prefix+query concatenation)", got)
			}
			xmlOK(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
				<Name>test-bucket</Name><IsTruncated>false</IsTruncated>
				<Contents><Key>docs/report.pdf</Key><Size>1</Size></Contents>
			</ListBucketResult>`)
		},
	})
	storageID := createBrowserStorageFixture(t, domainSvc, projectID, srv.URL, "")

	page, err := browserSvc.Search(context.Background(), storageID, "docs/", "rep", "", 50)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(page.Entries) != 1 || page.Entries[0].Key != "docs/report.pdf" {
		t.Fatalf("entries = %+v, want [{Key: docs/report.pdf}]", page.Entries)
	}
}

func TestObjectStorageBrowserGetObjectMetadata_Success(t *testing.T) {
	browserSvc, domainSvc, projectID := setupObjectStorageBrowserDB(t)

	lastModified := time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC)
	srv := fakeBrowserServer(t, fakeBrowserHandlers{
		headObject: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/pdf")
			w.Header().Set("Content-Length", "2048")
			w.Header().Set("ETag", `"deadbeef"`)
			w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
			w.Header().Set("x-amz-storage-class", "STANDARD_IA")
			w.Header().Set("x-amz-meta-owner", "alice")
			w.WriteHeader(http.StatusOK)
		},
	})
	storageID := createBrowserStorageFixture(t, domainSvc, projectID, srv.URL, "")

	md, err := browserSvc.GetObjectMetadata(context.Background(), storageID, "docs/report.pdf")
	if err != nil {
		t.Fatalf("GetObjectMetadata: %v", err)
	}
	if md.Key != "docs/report.pdf" {
		t.Errorf("key = %q, want docs/report.pdf", md.Key)
	}
	if md.SizeBytes != 2048 {
		t.Errorf("size = %d, want 2048", md.SizeBytes)
	}
	if md.ContentType != "application/pdf" {
		t.Errorf("content type = %q, want application/pdf", md.ContentType)
	}
	if md.ETag != `"deadbeef"` {
		t.Errorf("etag = %q, want \"deadbeef\"", md.ETag)
	}
	if md.StorageClass != "STANDARD_IA" {
		t.Errorf("storage class = %q, want STANDARD_IA", md.StorageClass)
	}
	if md.LastModified == nil {
		t.Fatalf("last modified missing")
	}
	if md.Metadata["owner"] != "alice" {
		t.Errorf("metadata[owner] = %q, want alice", md.Metadata["owner"])
	}
}

func TestObjectStorageBrowserGetObjectMetadata_MissingKeyReturnsNotFound(t *testing.T) {
	browserSvc, domainSvc, projectID := setupObjectStorageBrowserDB(t)
	srv := fakeBrowserServer(t, fakeBrowserHandlers{
		headObject: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		},
	})
	storageID := createBrowserStorageFixture(t, domainSvc, projectID, srv.URL, "")

	_, err := browserSvc.GetObjectMetadata(context.Background(), storageID, "missing.txt")
	if !errors.Is(err, ErrObjectStorageNotFound) {
		t.Fatalf("err = %v, want ErrObjectStorageNotFound", err)
	}
}

// TestObjectStorageBrowserGeneratePresignedDownloadURL_WellFormedShortLived
// needs no fake server at all: presigning a GetObject request is a pure,
// local, side-effect-free computation (the SDK never dials the endpoint to
// produce it), which is exactly why GET is defensible for this operation
// in the abstract even though this phase's handler ultimately uses POST
// per the plan's explicit routing decision -- see
// handlers/object_storage_browser.go's package doc comment.
func TestObjectStorageBrowserGeneratePresignedDownloadURL_WellFormedShortLived(t *testing.T) {
	browserSvc, domainSvc, projectID := setupObjectStorageBrowserDB(t)
	storageID := createBrowserStorageFixture(t, domainSvc, projectID, "http://127.0.0.1:19999", "tenant-a")

	ttl := 90 * time.Second
	before := time.Now()
	url, expiresAt, err := browserSvc.GeneratePresignedDownloadURL(context.Background(), storageID, "docs/report.pdf", ttl)
	if err != nil {
		t.Fatalf("GeneratePresignedDownloadURL: %v", err)
	}
	if !strings.HasPrefix(url, "http://127.0.0.1:19999/") {
		t.Errorf("url = %q, want it to target the configured endpoint", url)
	}
	if !strings.Contains(url, "X-Amz-Signature=") || !strings.Contains(url, "X-Amz-Expires=") {
		t.Errorf("url = %q, doesn't look like a presigned SigV4 URL", url)
	}
	if !strings.Contains(url, "tenant-a/docs/report.pdf") && !strings.Contains(url, "tenant-a%2Fdocs%2Freport.pdf") {
		t.Errorf("url = %q, want it to target the base_path-qualified key", url)
	}
	wantExpiry := before.Add(ttl)
	if expiresAt.Before(wantExpiry.Add(-5*time.Second)) || expiresAt.After(wantExpiry.Add(5*time.Second)) {
		t.Errorf("expiresAt = %v, want close to %v (a genuinely short-lived TTL, not a permanent link)", expiresAt, wantExpiry)
	}
}

func TestObjectStorageBrowserGetPreview_TooLargeNeverCallsGetObject(t *testing.T) {
	browserSvc, domainSvc, projectID := setupObjectStorageBrowserDB(t)
	srv := fakeBrowserServer(t, fakeBrowserHandlers{
		headObject: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", "999999999")
			w.WriteHeader(http.StatusOK)
		},
		getObject: func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("GetObject must never be called when the object exceeds maxBytes")
			w.WriteHeader(http.StatusInternalServerError)
		},
	})
	storageID := createBrowserStorageFixture(t, domainSvc, projectID, srv.URL, "")

	_, err := browserSvc.GetPreview(context.Background(), storageID, "big.txt", 1024)
	if !errors.Is(err, ErrObjectStoragePreviewTooLarge) {
		t.Fatalf("err = %v, want ErrObjectStoragePreviewTooLarge", err)
	}
}

func TestObjectStorageBrowserGetPreview_UnsupportedContentTypeNeverCallsGetObject(t *testing.T) {
	browserSvc, domainSvc, projectID := setupObjectStorageBrowserDB(t)
	srv := fakeBrowserServer(t, fakeBrowserHandlers{
		headObject: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
		},
		getObject: func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("GetObject must never be called for an unsupported (binary) content type")
			w.WriteHeader(http.StatusInternalServerError)
		},
	})
	storageID := createBrowserStorageFixture(t, domainSvc, projectID, srv.URL, "")

	_, err := browserSvc.GetPreview(context.Background(), storageID, "image.png", 5*1024*1024)
	if !errors.Is(err, ErrObjectStoragePreviewUnsupported) {
		t.Fatalf("err = %v, want ErrObjectStoragePreviewUnsupported", err)
	}
}

func TestObjectStorageBrowserGetPreview_SuccessTextContent(t *testing.T) {
	browserSvc, domainSvc, projectID := setupObjectStorageBrowserDB(t)
	body := []byte("hello world, this is a text preview")
	srv := fakeBrowserServer(t, fakeBrowserHandlers{
		headObject: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
		},
		getObject: func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Range"); got == "" {
				t.Errorf("GetObject request missing a Range header")
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(body)-1, len(body)))
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(body)
		},
	})
	storageID := createBrowserStorageFixture(t, domainSvc, projectID, srv.URL, "")

	preview, err := browserSvc.GetPreview(context.Background(), storageID, "notes.txt", 5*1024*1024)
	if err != nil {
		t.Fatalf("GetPreview: %v", err)
	}
	if preview.Encoding != "utf-8" {
		t.Errorf("encoding = %q, want utf-8", preview.Encoding)
	}
	if preview.Content != string(body) {
		t.Errorf("content = %q, want %q", preview.Content, string(body))
	}
	if preview.Truncated {
		t.Errorf("truncated = true, want false")
	}
	if preview.ContentType != "text/plain; charset=utf-8" {
		t.Errorf("content type = %q, want text/plain; charset=utf-8", preview.ContentType)
	}
}

func TestObjectStorageBrowserGetPreview_InvalidUTF8FallsBackToBase64(t *testing.T) {
	browserSvc, domainSvc, projectID := setupObjectStorageBrowserDB(t)
	body := []byte{0xff, 0xfe, 0x00, 0x01, 0x02} // not valid UTF-8
	srv := fakeBrowserServer(t, fakeBrowserHandlers{
		headObject: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
		},
		getObject: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(body)-1, len(body)))
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(body)
		},
	})
	storageID := createBrowserStorageFixture(t, domainSvc, projectID, srv.URL, "")

	preview, err := browserSvc.GetPreview(context.Background(), storageID, "weird.dat", 5*1024*1024)
	if err != nil {
		t.Fatalf("GetPreview: %v", err)
	}
	if preview.Encoding != "base64" {
		t.Errorf("encoding = %q, want base64", preview.Encoding)
	}
	decoded, decErr := base64.StdEncoding.DecodeString(preview.Content)
	if decErr != nil {
		t.Fatalf("content isn't valid base64: %v", decErr)
	}
	if !bytes.Equal(decoded, body) {
		t.Errorf("decoded content = %v, want %v", decoded, body)
	}
}
