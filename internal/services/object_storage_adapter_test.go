package services

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	smithy "github.com/aws/smithy-go"
)

// fakeS3Server stands up an in-process HTTP server that always answers
// with the given status code and body -- enough to drive
// TestObjectStorageConnection's HeadBucket probe through the real AWS SDK
// without any real AWS credentials or network access, per plan decision
// #10 ("in-process httptest fake-S3 server for deterministic
// failure-path tests").
func fakeS3Server(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testConn(t *testing.T, endpoint string) ObjectStorageConnection {
	t.Helper()
	return ObjectStorageConnection{
		Provider: "S3_COMPATIBLE", Endpoint: endpoint, Region: "us-east-1", Bucket: "test-bucket",
		AccessKeyID: "AKIAFAKE", SecretAccessKey: "fakesecret",
		ConnectTimeout: 5 * time.Second, CommandTimeout: 5 * time.Second,
	}
}

// Real-world note (see classifyObjectStorageError's own doc comment):
// HeadBucket is an HTTP HEAD request, so no server -- real S3 included --
// can deliver a response body for one; net/http silently discards
// whatever fakeS3Server's handler writes. That means only the HTTP status
// code reaches the SDK's error classification for these two cases, which
// is exactly what real AWS S3 does too (403 -> ACCESS_DENIED, 404 ->
// NOT_FOUND, both derived from the status alone). Credential-specific
// (AUTH_FAILED) classification is verified separately below, directly
// against classifyObjectStorageError, since no server can produce a body
// on a HEAD response to exercise it end-to-end.

func TestObjectStorageConnection_AccessDenied(t *testing.T) {
	srv := fakeS3Server(t, http.StatusForbidden, `<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`)
	status, err := TestObjectStorageConnection(context.Background(), testConn(t, srv.URL))
	if status != ObjectStorageStatusAccessDenied {
		t.Fatalf("status = %v, want ACCESS_DENIED", status)
	}
	if !errors.Is(err, ErrObjectStorageAccessDenied) {
		t.Errorf("err = %v, want wrapping ErrObjectStorageAccessDenied", err)
	}
}

func TestObjectStorageConnection_NotFound(t *testing.T) {
	srv := fakeS3Server(t, http.StatusNotFound, `<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`)
	status, err := TestObjectStorageConnection(context.Background(), testConn(t, srv.URL))
	if status != ObjectStorageStatusNotFound {
		t.Fatalf("status = %v, want NOT_FOUND", status)
	}
	if !errors.Is(err, ErrObjectStorageNotFound) {
		t.Errorf("err = %v, want wrapping ErrObjectStorageNotFound", err)
	}
}

func TestObjectStorageConnection_Timeout(t *testing.T) {
	// A handler that hangs well past the connection's short deadline --
	// drives the real timeout path through TestObjectStorageConnection
	// end to end (context.DeadlineExceeded), not just the classifier.
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	// Cleanups run LIFO: closing block (unblocking the handler) must
	// happen before srv.Close(), which otherwise waits forever for the
	// still-blocked in-flight request to finish -- so register srv.Close
	// first and the unblock second.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(block) })

	conn := testConn(t, srv.URL)
	conn.ConnectTimeout = 200 * time.Millisecond
	conn.CommandTimeout = 200 * time.Millisecond

	status, err := TestObjectStorageConnection(context.Background(), conn)
	if status != ObjectStorageStatusTimeout {
		t.Fatalf("status = %v, want TIMEOUT", status)
	}
	if !errors.Is(err, ErrObjectStorageTimeout) {
		t.Errorf("err = %v, want wrapping ErrObjectStorageTimeout", err)
	}
}

// TestClassifyObjectStorageError_AuthFailed exercises the
// credential-specific classification branch directly against a
// constructed smithy.GenericAPIError -- HeadBucket's real HTTP HEAD
// semantics mean no httptest server can deliver an error body carrying an
// InvalidAccessKeyId/SignatureDoesNotMatch code end to end (see the
// package doc comment above), but the classifier itself must still
// recognize these codes correctly for any provider/call path that does
// supply one.
func TestClassifyObjectStorageError_AuthFailed(t *testing.T) {
	cases := []string{"InvalidAccessKeyId", "SignatureDoesNotMatch", "ExpiredToken", "InvalidClientTokenId"}
	for _, code := range cases {
		t.Run(code, func(t *testing.T) {
			err := &smithy.GenericAPIError{Code: code, Message: "credential rejected"}
			classified := classifyObjectStorageError(err)
			if !errors.Is(classified, ErrObjectStorageAuth) {
				t.Errorf("classified = %v, want wrapping ErrObjectStorageAuth", classified)
			}
			if got := ObjectStorageConnectionStatusFromError(classified); got != ObjectStorageStatusAuthFailed {
				t.Errorf("status = %v, want AUTH_FAILED", got)
			}
		})
	}
}

func TestClassifyObjectStorageError_NilIsConnected(t *testing.T) {
	if classified := classifyObjectStorageError(nil); classified != nil {
		t.Errorf("classifyObjectStorageError(nil) = %v, want nil", classified)
	}
	if status := ObjectStorageConnectionStatusFromError(nil); status != ObjectStorageStatusConnected {
		t.Errorf("status = %v, want CONNECTED", status)
	}
}

func TestClassifyObjectStorageError_TLSHandshakeFailure(t *testing.T) {
	err := errors.New(`Get "https://example.invalid/test-bucket": x509: certificate signed by unknown authority`)
	classified := classifyObjectStorageError(err)
	if !errors.Is(classified, ErrObjectStorageTLS) {
		t.Errorf("classified = %v, want wrapping ErrObjectStorageTLS", classified)
	}
	if got := ObjectStorageConnectionStatusFromError(classified); got != ObjectStorageStatusTLSError {
		t.Errorf("status = %v, want TLS_ERROR", got)
	}
}

func TestClassifyObjectStorageError_UnknownFallsBackToUnavailable(t *testing.T) {
	err := errors.New("connection reset by peer")
	classified := classifyObjectStorageError(err)
	if !errors.Is(classified, ErrObjectStorageConnection) {
		t.Errorf("classified = %v, want wrapping ErrObjectStorageConnection", classified)
	}
	if got := ObjectStorageConnectionStatusFromError(classified); got != ObjectStorageStatusUnavailable {
		t.Errorf("status = %v, want UNAVAILABLE", got)
	}
}
