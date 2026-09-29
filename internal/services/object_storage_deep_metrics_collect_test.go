package services

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeDeepS3Server stands up an in-process HTTP server that routes on the
// S3 REST sub-resource query string (?versioning, ?encryption,
// ?publicAccessBlock, ?policyStatus, ?object-lock, ?list-type=2) --
// confirmed against the AWS SDK v2 S3 serializers (serializers.go) rather
// than guessed -- so CollectObjectStorageDeepMetrics's five independent
// probes can each be answered differently in one fake server, per plan
// decision #10 ("in-process httptest fake-S3 server for deterministic
// failure-path tests").
type fakeDeepS3Handlers struct {
	versioning        func(w http.ResponseWriter)
	encryption        func(w http.ResponseWriter)
	publicAccessBlock func(w http.ResponseWriter)
	policyStatus      func(w http.ResponseWriter)
	objectLock        func(w http.ResponseWriter)
	listObjectsV2     func(w http.ResponseWriter, r *http.Request)
}

func fakeDeepS3Server(t *testing.T, h fakeDeepS3Handlers) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case q.Has("versioning") && h.versioning != nil:
			h.versioning(w)
		case q.Has("encryption") && h.encryption != nil:
			h.encryption(w)
		case q.Has("publicAccessBlock") && h.publicAccessBlock != nil:
			h.publicAccessBlock(w)
		case q.Has("policyStatus") && h.policyStatus != nil:
			h.policyStatus(w)
		case q.Has("object-lock") && h.objectLock != nil:
			h.objectLock(w)
		case q.Has("list-type") && h.listObjectsV2 != nil:
			h.listObjectsV2(w, r)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func xmlOK(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

func xmlError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(fmt.Sprintf(`<Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)))
}

// deepTestConn mirrors testConn (object_storage_adapter_test.go) but for
// S3_COMPATIBLE deep-metrics tests: CloudWatch is AWS_S3-only, so
// S3_COMPATIBLE always exercises the bounded-listing fallback, which is
// exactly what these tests want to verify without mocking CloudWatch.
func deepTestConn(t *testing.T, endpoint string) ObjectStorageConnection {
	t.Helper()
	conn := testConn(t, endpoint)
	conn.Provider = "S3_COMPATIBLE"
	return conn
}

func TestCollectObjectStorageDeepMetrics_Success(t *testing.T) {
	srv := fakeDeepS3Server(t, fakeDeepS3Handlers{
		versioning: func(w http.ResponseWriter) {
			xmlOK(w, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)
		},
		encryption: func(w http.ResponseWriter) {
			xmlOK(w, `<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`)
		},
		publicAccessBlock: func(w http.ResponseWriter) {
			xmlOK(w, `<PublicAccessBlockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`)
		},
		objectLock: func(w http.ResponseWriter) {
			xmlOK(w, `<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`)
		},
		listObjectsV2: func(w http.ResponseWriter, r *http.Request) {
			xmlOK(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>test-bucket</Name><Contents><Key>a.txt</Key><Size>100</Size></Contents><Contents><Key>b.txt</Key><Size>250</Size></Contents><IsTruncated>false</IsTruncated></ListBucketResult>`)
		},
	})

	result, err := CollectObjectStorageDeepMetrics(t.Context(), deepTestConn(t, srv.URL))
	if err != nil {
		t.Fatalf("CollectObjectStorageDeepMetrics: %v", err)
	}
	if result.VersioningStatus != "ENABLED" {
		t.Errorf("VersioningStatus = %q, want ENABLED", result.VersioningStatus)
	}
	if result.EncryptionStatus != "ENABLED" {
		t.Errorf("EncryptionStatus = %q, want ENABLED", result.EncryptionStatus)
	}
	if result.PublicAccess != "PRIVATE" {
		t.Errorf("PublicAccess = %q, want PRIVATE", result.PublicAccess)
	}
	if result.ObjectLockStatus != "ENABLED" {
		t.Errorf("ObjectLockStatus = %q, want ENABLED", result.ObjectLockStatus)
	}
	if result.ObjectCount == nil || *result.ObjectCount != 2 {
		t.Errorf("ObjectCount = %v, want 2 (from the bounded-listing fallback -- S3_COMPATIBLE has no CloudWatch)", result.ObjectCount)
	}
	if result.TotalSizeBytes == nil || *result.TotalSizeBytes != 350 {
		t.Errorf("TotalSizeBytes = %v, want 350", result.TotalSizeBytes)
	}
	if result.Partial {
		t.Errorf("Partial = true, want false (every probe succeeded): warning=%q", result.Warning)
	}
}

// TestCollectObjectStorageDeepMetrics_PartialFailure_OneProbeFails verifies
// the plan's explicit failure-isolation requirement: a single probe's
// failure (here, GetBucketEncryption returning AccessDenied) sets ONLY
// that field to UNKNOWN and never aborts the cycle -- every other fact is
// still collected correctly, and the result is marked Partial (not a hard
// error).
func TestCollectObjectStorageDeepMetrics_PartialFailure_OneProbeFails(t *testing.T) {
	srv := fakeDeepS3Server(t, fakeDeepS3Handlers{
		versioning: func(w http.ResponseWriter) {
			xmlOK(w, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Suspended</Status></VersioningConfiguration>`)
		},
		encryption: func(w http.ResponseWriter) {
			xmlError(w, http.StatusForbidden, "AccessDenied")
		},
		publicAccessBlock: func(w http.ResponseWriter) {
			// Not fully blocked (RestrictPublicBuckets=false) -- forces the
			// fallback to GetBucketPolicyStatus.
			xmlOK(w, `<PublicAccessBlockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>false</RestrictPublicBuckets></PublicAccessBlockConfiguration>`)
		},
		policyStatus: func(w http.ResponseWriter) {
			xmlOK(w, `<PolicyStatus><IsPublic>true</IsPublic></PolicyStatus>`)
		},
		objectLock: func(w http.ResponseWriter) {
			xmlError(w, http.StatusNotFound, "ObjectLockConfigurationNotFoundError")
		},
		listObjectsV2: func(w http.ResponseWriter, r *http.Request) {
			xmlOK(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>test-bucket</Name><Contents><Key>a.txt</Key><Size>10</Size></Contents><IsTruncated>false</IsTruncated></ListBucketResult>`)
		},
	})

	result, err := CollectObjectStorageDeepMetrics(t.Context(), deepTestConn(t, srv.URL))
	if err != nil {
		t.Fatalf("CollectObjectStorageDeepMetrics returned a hard error for a partial failure: %v", err)
	}
	if result.VersioningStatus != "DISABLED" {
		t.Errorf("VersioningStatus = %q, want DISABLED (Suspended)", result.VersioningStatus)
	}
	// The failed probe: must be UNKNOWN, never inferred as "probably
	// disabled".
	if result.EncryptionStatus != "UNKNOWN" {
		t.Errorf("EncryptionStatus = %q, want UNKNOWN after AccessDenied", result.EncryptionStatus)
	}
	// PublicAccessBlock didn't give a definitive PRIVATE answer, so the
	// PolicyStatus fallback's PUBLIC verdict must be used.
	if result.PublicAccess != "PUBLIC" {
		t.Errorf("PublicAccess = %q, want PUBLIC (from the GetBucketPolicyStatus fallback)", result.PublicAccess)
	}
	// ObjectLockConfigurationNotFoundError is a real "never enabled" fact,
	// not a probe failure.
	if result.ObjectLockStatus != "DISABLED" {
		t.Errorf("ObjectLockStatus = %q, want DISABLED (never configured)", result.ObjectLockStatus)
	}
	if result.ObjectCount == nil || *result.ObjectCount != 1 {
		t.Errorf("ObjectCount = %v, want 1 (bucket-scan fallback unaffected by the encryption probe's failure)", result.ObjectCount)
	}
	if !result.Partial {
		t.Errorf("Partial = false, want true (one probe failed)")
	}
	if !strings.Contains(result.Warning, "encryption") {
		t.Errorf("Warning = %q, want it to mention the failed encryption probe", result.Warning)
	}
}

// TestCollectObjectStorageDeepMetrics_BoundedListingNeverUnbounded verifies
// the hard "no unbounded bucket scan, ever" constraint: a bucket that
// claims to be truncated forever is only ever walked
// objectStorageDeepListMaxPages times, never more, and the result comes
// back Partial=true (a real but honest undercount).
func TestCollectObjectStorageDeepMetrics_BoundedListingNeverUnbounded(t *testing.T) {
	var pageRequests int64
	srv := fakeDeepS3Server(t, fakeDeepS3Handlers{
		versioning:        func(w http.ResponseWriter) { xmlError(w, http.StatusForbidden, "AccessDenied") },
		encryption:        func(w http.ResponseWriter) { xmlError(w, http.StatusForbidden, "AccessDenied") },
		publicAccessBlock: func(w http.ResponseWriter) { xmlError(w, http.StatusForbidden, "AccessDenied") },
		policyStatus:      func(w http.ResponseWriter) { xmlError(w, http.StatusForbidden, "AccessDenied") },
		objectLock:        func(w http.ResponseWriter) { xmlError(w, http.StatusForbidden, "AccessDenied") },
		listObjectsV2: func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt64(&pageRequests, 1)
			xmlOK(w, fmt.Sprintf(`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>test-bucket</Name><Contents><Key>obj-%d.txt</Key><Size>1</Size></Contents><IsTruncated>true</IsTruncated><NextContinuationToken>tok-%d</NextContinuationToken></ListBucketResult>`, n, n))
		},
	})

	result, err := CollectObjectStorageDeepMetrics(t.Context(), deepTestConn(t, srv.URL))
	if err != nil {
		t.Fatalf("CollectObjectStorageDeepMetrics: %v", err)
	}
	if got := atomic.LoadInt64(&pageRequests); got != objectStorageDeepListMaxPages {
		t.Errorf("ListObjectsV2 called %d times, want exactly the %d-page cap -- never an unbounded scan", got, objectStorageDeepListMaxPages)
	}
	if result.ObjectCount == nil || *result.ObjectCount != objectStorageDeepListMaxPages {
		t.Errorf("ObjectCount = %v, want %d (one object per capped page)", result.ObjectCount, objectStorageDeepListMaxPages)
	}
	if !result.Partial {
		t.Errorf("Partial = false, want true -- the cap was hit before the bucket was fully listed, so the count is an undercount")
	}
}
