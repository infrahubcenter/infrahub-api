package services

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// ErrUnsafePackageName is returned when a package name selected for
// execution fails the strict allowlist check. Preview rendering
// (os_update_command_builder.go) silently drops unsafe names since it's
// display-only; actual execution must instead refuse outright -- silently
// dropping a package from a real, admin-approved command would execute
// something other than what was approved.
var ErrUnsafePackageName = errors.New("package name contains characters that are not allowed")

// ValidatePackageNamesForExecution rejects the whole set if any name
// fails safePackageNamePattern, rather than silently filtering (spec:
// "package_name values like 'nginx; rm -rf /' ... must all be rejected").
// The pattern itself (only letters/digits/+._:~- ) makes every listed
// shell metacharacter (; & | $ ` > < ( ) and newline) structurally
// impossible to match, so this is a defense-in-depth allowlist check, not
// a blocklist/escaping scheme.
func ValidatePackageNamesForExecution(names []string) error {
	for _, n := range names {
		if !safePackageNamePattern.MatchString(n) {
			return ErrUnsafePackageName
		}
	}
	return nil
}

// HashCommand returns the SHA-256 hex digest of an executed/to-be-executed
// command string, for audit-verification that the executed command
// matches what was approved (spec: "not a secret -- an integrity check").
func HashCommand(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])
}
