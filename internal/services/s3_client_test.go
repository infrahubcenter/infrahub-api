package services

import (
	"net/http"
	"testing"
)

// TestNewS3Client_PerProviderOptions asserts newS3Client's only
// per-provider behavior -- UsePathStyle and BaseEndpoint -- without
// dialing out (config.LoadDefaultConfig with static credentials never
// makes a network call on its own).
func TestNewS3Client_PerProviderOptions(t *testing.T) {
	cases := []struct {
		name             string
		provider         string
		endpoint         string
		wantUsePathStyle bool
		wantEndpoint     string
	}{
		{"AWS_S3 uses virtual-hosted style, no override", "AWS_S3", "", false, ""},
		{"AWS_S3 with a custom endpoint still keeps virtual-hosted style", "AWS_S3", "https://s3.us-east-1.amazonaws.com", false, "https://s3.us-east-1.amazonaws.com"},
		{"DigitalOcean Spaces uses path style", "DIGITALOCEAN_SPACES", "https://nyc3.digitaloceanspaces.com", true, "https://nyc3.digitaloceanspaces.com"},
		{"MinIO uses path style", "MINIO", "http://127.0.0.1:9000", true, "http://127.0.0.1:9000"},
		{"generic S3-compatible uses path style", "S3_COMPATIBLE", "http://127.0.0.1:9001", true, "http://127.0.0.1:9001"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := ObjectStorageConnection{
				Provider: tc.provider, Endpoint: tc.endpoint, Region: "us-east-1",
				Bucket: "test-bucket", AccessKeyID: "AKIAFAKE", SecretAccessKey: "fakesecret",
			}
			client, err := newS3Client(conn)
			if err != nil {
				t.Fatalf("newS3Client: %v", err)
			}
			opts := client.Options()
			if opts.UsePathStyle != tc.wantUsePathStyle {
				t.Errorf("UsePathStyle = %v, want %v", opts.UsePathStyle, tc.wantUsePathStyle)
			}
			if tc.wantEndpoint == "" {
				if opts.BaseEndpoint != nil {
					t.Errorf("BaseEndpoint = %v, want nil", *opts.BaseEndpoint)
				}
				return
			}
			if opts.BaseEndpoint == nil || *opts.BaseEndpoint != tc.wantEndpoint {
				t.Errorf("BaseEndpoint = %v, want %v", opts.BaseEndpoint, tc.wantEndpoint)
			}
		})
	}
}

// TestNewS3Client_TLSSkipVerify asserts the InsecureSkipVerify opt-in is
// wired only when explicitly requested, never by default -- the SDK
// always resolves *some* HTTPClient (its own *awshttp.BuildableClient)
// before our functional option runs, so the meaningful assertion is which
// concrete type ends up installed, not nil-vs-non-nil.
func TestNewS3Client_TLSSkipVerify(t *testing.T) {
	base := ObjectStorageConnection{
		Provider: "MINIO", Endpoint: "https://127.0.0.1:9000", Region: "us-east-1",
		Bucket: "test-bucket", AccessKeyID: "AKIAFAKE", SecretAccessKey: "fakesecret",
	}

	withoutSkip, err := newS3Client(base)
	if err != nil {
		t.Fatalf("newS3Client: %v", err)
	}
	if _, isPlainClient := withoutSkip.Options().HTTPClient.(*http.Client); isPlainClient {
		t.Errorf("HTTPClient should stay the SDK's own default when TLSSkipVerify is false, got a plain *http.Client override")
	}

	skip := base
	skip.TLSSkipVerify = true
	withSkip, err := newS3Client(skip)
	if err != nil {
		t.Fatalf("newS3Client: %v", err)
	}
	client, ok := withSkip.Options().HTTPClient.(*http.Client)
	if !ok {
		t.Fatalf("HTTPClient = %T, want *http.Client override when TLSSkipVerify is true", withSkip.Options().HTTPClient)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Errorf("expected an *http.Transport with TLSClientConfig.InsecureSkipVerify = true")
	}
}
