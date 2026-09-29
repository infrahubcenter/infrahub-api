package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithy "github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// TestObjectStorageConnection runs exactly one backend-defined, read-only
// HeadBucket call against the configured bucket -- never lists objects,
// never accepts a client-supplied operation of any kind. Returns the
// classified status alongside a typed error (nil on success); callers
// persist/display the status, never err's message directly, since the
// underlying AWS SDK error can embed endpoint/query detail.
func TestObjectStorageConnection(ctx context.Context, conn ObjectStorageConnection) (ObjectStorageConnectionStatus, error) {
	timeout := conn.ConnectTimeout
	if timeout <= 0 {
		timeout = conn.CommandTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, err := newS3Client(conn)
	if err != nil {
		classified := fmt.Errorf("%w: %v", ErrObjectStorageConnection, err)
		return ObjectStorageConnectionStatusFromError(classified), classified
	}

	_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &conn.Bucket})
	classified := classifyObjectStorageError(err)
	return ObjectStorageConnectionStatusFromError(classified), classified
}

// classifyObjectStorageError turns a raw AWS SDK / transport error from a
// HeadBucket call into one of this package's typed object-storage errors.
// Real-world note: HeadBucket is an HTTP HEAD request, and per HTTP
// semantics no server (compliant or not, real S3 included) can deliver a
// response body for one -- net/http silently discards it -- so AWS's own
// HeadBucket error responses carry no XML error body, only an HTTP status
// code translated to a generic code (e.g. 403 -> "Forbidden", 404 ->
// "NotFound"). The credential-specific error codes below
// (InvalidAccessKeyId/SignatureDoesNotMatch/etc) are checked defensively
// for any provider that deviates from that norm, but 403 without further
// detail is classified ACCESS_DENIED, matching the spec's stated mapping
// and this project's inability to distinguish "bad credentials" from
// "valid credentials, no permission" on a bodyless HEAD response alone.
func classifyObjectStorageError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %v", ErrObjectStorageTimeout, err)
	}
	if isTLSError(err) {
		return fmt.Errorf("%w: %v", ErrObjectStorageTLS, err)
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NoSuchBucket", "NotFound":
			return fmt.Errorf("%w: %s", ErrObjectStorageNotFound, apiErr.ErrorMessage())
		case "InvalidAccessKeyId", "SignatureDoesNotMatch", "InvalidClientTokenId", "ExpiredToken", "TokenRefreshRequired", "InvalidSecurity", "InvalidToken":
			return fmt.Errorf("%w: %s", ErrObjectStorageAuth, apiErr.ErrorMessage())
		case "AccessDenied", "Forbidden", "AllAccessDisabled":
			return fmt.Errorf("%w: %s", ErrObjectStorageAccessDenied, apiErr.ErrorMessage())
		}
	}

	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.HTTPStatusCode() {
		case http.StatusNotFound:
			return fmt.Errorf("%w: http %d", ErrObjectStorageNotFound, respErr.HTTPStatusCode())
		case http.StatusForbidden:
			return fmt.Errorf("%w: http %d", ErrObjectStorageAccessDenied, respErr.HTTPStatusCode())
		case http.StatusUnauthorized:
			return fmt.Errorf("%w: http %d", ErrObjectStorageAuth, respErr.HTTPStatusCode())
		}
	}

	return fmt.Errorf("%w: %v", ErrObjectStorageConnection, err)
}

// isTLSError reports whether err's message indicates a TLS/certificate
// handshake failure -- string-matched like classifyMySQLError/
// classifyRedisError (direct_database_adapter.go), since Go's TLS/x509
// error types don't implement a single common interface worth
// errors.As-ing on.
func isTLSError(err error) bool {
	return containsAny(err.Error(), "tls:", "x509:", "certificate signed by unknown authority", "certificate is not trusted", "certificate has expired", "handshake failure")
}
