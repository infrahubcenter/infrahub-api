// This file exercises the standalone object storage read-only browser's
// HTTP surface (Step 17 Phase 4): permission-tier IDOR on every new
// endpoint (List/Search/Metadata/Preview require object_storage.browser;
// RequestDownload requires object_storage.download alone, NOT additionally
// object_storage.browser), path-traversal rejection at the HTTP layer, and
// that GetObjectMetadata/RequestDownload write the documented audit
// events with only the object key in Metadata (never content, never the
// generated presigned URL). Mirrors object_storage_test.go's fixture/IDOR
// shape exactly. RequestDownload is POST -- see
// handlers/object_storage_browser.go's package doc comment for the
// GET-vs-POST reasoning and its resulting divergence from the frontend
// agent's assumed GET contract.
package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/services"
)

// fakeObjectBrowserHandlers/fakeObjectBrowserServer route a fake-S3
// httptest server the same way object_storage_browser_test.go (internal/
// services) does: ListObjectsV2 on ?list-type=2, HeadObject/GetObject on
// plain HTTP method against the object's path.
type fakeObjectBrowserHandlers struct {
	listObjects func(w http.ResponseWriter, r *http.Request)
	headObject  func(w http.ResponseWriter, r *http.Request)
	getObject   func(w http.ResponseWriter, r *http.Request)
}

func fakeObjectBrowserServer(t *testing.T, h fakeObjectBrowserHandlers) *httptest.Server {
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

// === GET /api/object-storage/:id/objects (List) ===

func TestObjectStorageObjectsList_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, _ := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String()+"/objects")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member objects list = %d, want 404 (existence must not be disclosed)", resp.StatusCode)
	}
}

// A member holding only object_storage.view (not .browser) must be
// rejected the same 404-not-403 way as a member with zero permissions --
// permission-tier IDOR, same shape as Phase 2/3's view-vs-monitor checks.
func TestObjectStorageObjectsList_ViewOnlyMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String()+"/objects")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("view-only member objects list = %d, want 404 (object_storage.browser required)", resp.StatusCode)
	}
}

func TestObjectStorageObjectsList_BrowserMember_ReturnsEntries(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)

	srv := fakeObjectBrowserServer(t, fakeObjectBrowserHandlers{
		listObjects: func(w http.ResponseWriter, r *http.Request) {
			xmlOKResponse(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
				<Name>test-bucket</Name><IsTruncated>false</IsTruncated>
				<Contents><Key>report.pdf</Key><Size>1024</Size></Contents>
				<CommonPrefixes><Prefix>docs/</Prefix></CommonPrefixes>
			</ListBucketResult>`)
		},
	})
	defer srv.Close()

	osID, resourceID := e.createObjectStorageFixtureAtEndpoint(t, project, srv.URL)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageBrowser)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/object-storage/"+osID.String()+"/objects")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("browser member objects list = %d, want 200", resp.StatusCode)
	}
	if body["bucket"] != "test-bucket" {
		t.Errorf("bucket = %v, want test-bucket", body["bucket"])
	}
	entries, ok := body["entries"].([]any)
	if !ok || len(entries) != 2 {
		t.Fatalf("entries = %v, want exactly 2", body["entries"])
	}
}

// A prefix attempting path traversal must be rejected with 400 before ever
// reaching S3 -- the fake server below fails the test if it's ever hit.
func TestObjectStorageObjectsList_PathTraversalRejected_NeverReachesS3(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)

	srv := fakeObjectBrowserServer(t, fakeObjectBrowserHandlers{
		listObjects: func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("ListObjectsV2 must never be called for a path-traversal prefix")
			w.WriteHeader(http.StatusInternalServerError)
		},
	})
	defer srv.Close()

	osID, resourceID := e.createObjectStorageFixtureAtEndpoint(t, project, srv.URL)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageBrowser)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String()+"/objects?prefix=../../etc")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("path-traversal prefix = %d, want 400", resp.StatusCode)
	}
}

func TestObjectStorageObjectsList_CrossStorageIDOR(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	storageA, resourceA := e.createObjectStorageFixture(t, project)
	storageB, _ := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceA, services.PermObjectStorageBrowser)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	// Storage A has no reachable fake endpoint configured (points at a
	// closed port), so the call itself may fail upstream -- what this test
	// verifies is authorization, not S3 connectivity: A must not 404, B
	// must.
	aResp, _ := e.get(t, client, "/api/object-storage/"+storageA.String()+"/objects")
	if aResp.StatusCode == http.StatusNotFound {
		t.Fatalf("authorized storage A objects list = 404, want anything but 404 (IDOR check, not a connectivity check)")
	}
	bResp, _ := e.get(t, client, "/api/object-storage/"+storageB.String()+"/objects")
	if bResp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized storage B objects list = %d, want 404 (access to A must not leak B)", bResp.StatusCode)
	}
}

// === GET /api/object-storage/:id/objects/search ===

func TestObjectStorageObjectsSearch_BrowserMember_ReturnsFilteredEntries(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)

	srv := fakeObjectBrowserServer(t, fakeObjectBrowserHandlers{
		listObjects: func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("prefix"); got != "rep" {
				t.Errorf("search prefix sent to S3 = %q, want rep", got)
			}
			xmlOKResponse(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
				<Name>test-bucket</Name><IsTruncated>false</IsTruncated>
				<Contents><Key>report.pdf</Key><Size>1</Size></Contents>
			</ListBucketResult>`)
		},
	})
	defer srv.Close()

	osID, resourceID := e.createObjectStorageFixtureAtEndpoint(t, project, srv.URL)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageBrowser)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/object-storage/"+osID.String()+"/objects/search?q=rep")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("browser member search = %d, want 200", resp.StatusCode)
	}
	entries, ok := body["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("entries = %v, want exactly 1", body["entries"])
	}
}

func TestObjectStorageObjectsSearch_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, _ := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String()+"/objects/search?q=x")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member search = %d, want 404", resp.StatusCode)
	}
}

// === GET /api/object-storage/:id/objects/metadata ===

func TestObjectStorageObjectsMetadata_BrowserMember_ReturnsMetadataAndAudits(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)

	srv := fakeObjectBrowserServer(t, fakeObjectBrowserHandlers{
		headObject: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/pdf")
			w.Header().Set("Content-Length", "2048")
			w.Header().Set("ETag", `"abc"`)
			w.WriteHeader(http.StatusOK)
		},
	})
	defer srv.Close()

	osID, resourceID := e.createObjectStorageFixtureAtEndpoint(t, project, srv.URL)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageBrowser)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/object-storage/"+osID.String()+"/objects/metadata?key=report.pdf")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("browser member metadata = %d, want 200", resp.StatusCode)
	}
	if body["size_bytes"] != float64(2048) {
		t.Errorf("size_bytes = %v, want 2048", body["size_bytes"])
	}
	if body["content_type"] != "application/pdf" {
		t.Errorf("content_type = %v, want application/pdf", body["content_type"])
	}
	assertAuditEventExists(t, e, "OBJECT_STORAGE", resourceID, services.AuditObjectStorageObjectViewed)
}

func TestObjectStorageObjectsMetadata_ViewOnlyMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String()+"/objects/metadata?key=report.pdf")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("view-only member metadata = %d, want 404 (object_storage.browser required)", resp.StatusCode)
	}
}

func TestObjectStorageObjectsMetadata_PathTraversalKeyRejected(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)

	srv := fakeObjectBrowserServer(t, fakeObjectBrowserHandlers{
		headObject: func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("HeadObject must never be called for a path-traversal key")
			w.WriteHeader(http.StatusInternalServerError)
		},
	})
	defer srv.Close()

	osID, resourceID := e.createObjectStorageFixtureAtEndpoint(t, project, srv.URL)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageBrowser)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String()+"/objects/metadata?key=../secret")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("path-traversal key metadata = %d, want 400", resp.StatusCode)
	}
}

// === POST /api/object-storage/:id/objects/download ===

// A member with object_storage.browser but NOT object_storage.download
// must be rejected -- these are two independent, separately grantable
// permissions with no built-in hierarchy (see
// handlers/object_storage_browser.go's RequestDownload doc comment for the
// full reasoning), so browser alone must never be enough for a download
// link.
func TestObjectStorageObjectsDownload_BrowserWithoutDownloadMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageBrowser)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/object-storage/"+osID.String()+"/objects/download?key=report.pdf", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("browser-without-download member download = %d, want 404 (object_storage.download required)", resp.StatusCode)
	}
}

func TestObjectStorageObjectsDownload_DownloadMember_ReturnsURLAndAudits_NeverLogsURL(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, resourceID := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	// Deliberately grants ONLY object_storage.download, without .browser --
	// this must be sufficient on its own per the plan's per-endpoint
	// permission model.
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageDownload)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/object-storage/"+osID.String()+"/objects/download?key=report.pdf", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download-only member download = %d, want 200", resp.StatusCode)
	}
	url, _ := body["url"].(string)
	if url == "" {
		t.Fatalf("url missing from download response: %v", body)
	}
	if body["expires_at"] == nil {
		t.Errorf("expires_at missing from download response: %v", body)
	}

	assertAuditEventExists(t, e, "OBJECT_STORAGE", resourceID, services.AuditObjectStorageObjectDownloaded)

	// The audit log must carry the key, never the generated URL (which
	// embeds a temporary credential in its query string).
	logs, err := e.store.ListAuditLogsByResource(context.Background(), generated.ListAuditLogsByResourceParams{
		ResourceID: pgutil.NullUUID(&resourceID), Limit: 500,
	})
	if err != nil {
		t.Fatalf("list audit logs: %v", err)
	}
	found := false
	for _, l := range logs {
		if l.Action != services.AuditObjectStorageObjectDownloaded {
			continue
		}
		found = true
		if len(l.Metadata) > 0 {
			metaStr := string(l.Metadata)
			if !strings.Contains(metaStr, "report.pdf") {
				t.Errorf("audit metadata = %s, want it to contain the object key", metaStr)
			}
			if strings.Contains(metaStr, "X-Amz-Signature") || strings.Contains(metaStr, url) {
				t.Errorf("audit metadata leaked the presigned download URL: %s", metaStr)
			}
		}
	}
	if !found {
		t.Fatalf("no OBJECT_STORAGE_OBJECT_DOWNLOADED audit row found")
	}
}

func TestObjectStorageObjectsDownload_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, _ := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/object-storage/"+osID.String()+"/objects/download?key=report.pdf", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member download = %d, want 404", resp.StatusCode)
	}
}

func TestObjectStorageObjectsDownload_CrossStorageIDOR(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	storageA, resourceA := e.createObjectStorageFixture(t, project)
	storageB, _ := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceA, services.PermObjectStorageDownload)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	aResp, _ := e.do(t, client, http.MethodPost, "/api/object-storage/"+storageA.String()+"/objects/download?key=x", nil)
	if aResp.StatusCode != http.StatusOK {
		t.Fatalf("authorized storage A download = %d, want 200", aResp.StatusCode)
	}
	bResp, _ := e.do(t, client, http.MethodPost, "/api/object-storage/"+storageB.String()+"/objects/download?key=x", nil)
	if bResp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized storage B download = %d, want 404 (access to A must not leak B)", bResp.StatusCode)
	}
}

// === GET /api/object-storage/:id/objects/preview ===

func TestObjectStorageObjectsPreview_BrowserMember_ReturnsTextPreview(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	body := []byte("hello preview")

	srv := fakeObjectBrowserServer(t, fakeObjectBrowserHandlers{
		headObject: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
		},
		getObject: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		},
	})
	defer srv.Close()

	osID, resourceID := e.createObjectStorageFixtureAtEndpoint(t, project, srv.URL)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageBrowser)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, respBody := e.get(t, client, "/api/object-storage/"+osID.String()+"/objects/preview?key=notes.txt")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("browser member preview = %d, want 200", resp.StatusCode)
	}
	if respBody["encoding"] != "utf-8" {
		t.Errorf("encoding = %v, want utf-8", respBody["encoding"])
	}
	if respBody["content"] != string(body) {
		t.Errorf("content = %v, want %q", respBody["content"], string(body))
	}
}

func TestObjectStorageObjectsPreview_TooLarge_Returns413WithoutCallingGetObject(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)

	srv := fakeObjectBrowserServer(t, fakeObjectBrowserHandlers{
		headObject: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", "999999999")
			w.WriteHeader(http.StatusOK)
		},
		getObject: func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("GetObject must never be called for an over-limit object")
			w.WriteHeader(http.StatusInternalServerError)
		},
	})
	defer srv.Close()

	osID, resourceID := e.createObjectStorageFixtureAtEndpoint(t, project, srv.URL)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageBrowser)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String()+"/objects/preview?key=huge.txt")
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit preview = %d, want 413", resp.StatusCode)
	}
}

func TestObjectStorageObjectsPreview_UnsupportedContentType_Returns415(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)

	srv := fakeObjectBrowserServer(t, fakeObjectBrowserHandlers{
		headObject: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
		},
		getObject: func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("GetObject must never be called for an unsupported content type")
			w.WriteHeader(http.StatusInternalServerError)
		},
	})
	defer srv.Close()

	osID, resourceID := e.createObjectStorageFixtureAtEndpoint(t, project, srv.URL)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermObjectStorageBrowser)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String()+"/objects/preview?key=image.png")
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("unsupported-content-type preview = %d, want 415", resp.StatusCode)
	}
}

func TestObjectStorageObjectsPreview_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, _ := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/object-storage/"+osID.String()+"/objects/preview?key=x")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member preview = %d, want 404", resp.StatusCode)
	}
}

// === No write/delete/upload route exists anywhere in this feature ===

func TestObjectStorageObjects_NoMutatingRouteExists(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, _ := e.createObjectStorageFixture(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		resp, _ := e.do(t, client, method, "/api/object-storage/"+osID.String()+"/objects", nil)
		if resp.StatusCode == http.StatusOK {
			t.Errorf("%s /objects = 200, want no mutating route to exist for the browser", method)
		}
	}
	// POST /objects (as opposed to /objects/download) must not exist either.
	resp, _ := e.do(t, client, http.MethodPost, "/api/object-storage/"+osID.String()+"/objects", nil)
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		t.Errorf("POST /objects = %d, want no such route", resp.StatusCode)
	}
}
