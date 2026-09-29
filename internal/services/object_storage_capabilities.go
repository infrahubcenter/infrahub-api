package services

// ObjectStorageCapabilities is the flat, per-provider capability map the
// frontend detail page uses to hide (not merely disable) tabs/sections it
// has no data for -- mirrors the spec's capability-gating rule of "hidden,
// not shown-with-message" for a consistent single rule across the page.
type ObjectStorageCapabilities struct {
	Metrics        bool `json:"metrics"`
	Browser        bool `json:"browser"`
	ObjectMetadata bool `json:"object_metadata"`
	Download       bool `json:"download"`
	Logs           bool `json:"logs"`
	Versioning     bool `json:"versioning"`
	Encryption     bool `json:"encryption"`
}

// CapabilitiesForProvider returns the capability set for a given object
// storage provider. All four supported providers (AWS_S3,
// DIGITALOCEAN_SPACES, MINIO, S3_COMPATIBLE) get the same set today --
// they all speak the same S3 API surface this project uses (HeadBucket,
// GetBucketVersioning/Encryption/PublicAccessBlock/ObjectLockConfiguration,
// ListObjectsV2/HeadObject). Logs is false for every provider: this step
// ships no log integration of any kind (no CloudTrail/access-log
// ingestion), so the Logs tab must stay hidden everywhere rather than
// falsely implying it exists for some providers and not others.
func CapabilitiesForProvider(provider string) ObjectStorageCapabilities {
	return ObjectStorageCapabilities{
		Metrics:        true,
		Browser:        true,
		ObjectMetadata: true,
		Download:       true,
		Logs:           false,
		Versioning:     true,
		Encryption:     true,
	}
}
