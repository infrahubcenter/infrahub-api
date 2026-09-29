package services

import (
	"context"
	"errors"
	"net"
	"strings"
)

// SSH/connection error codes (Step 5 spec §50). Handlers map these to safe
// HTTP responses (internal/handlers/ssh_errors.go); none of them ever
// carry a private key, ciphertext, or raw SSH library internals.
const (
	ErrCodeInvalidCredential = "INVALID_CREDENTIAL"
	ErrCodeAuthFailed        = "SSH_AUTHENTICATION_FAILED"
	ErrCodeTimeout           = "SSH_CONNECTION_TIMEOUT"
	ErrCodeRefused           = "SSH_CONNECTION_REFUSED"
	ErrCodeDNSFailure        = "SSH_DNS_FAILURE"
	ErrCodeHostUnreachable   = "SSH_HOST_UNREACHABLE"
	ErrCodeHostKeyUnknown    = "HOST_KEY_UNKNOWN"
	ErrCodeHostKeyChanged    = "HOST_KEY_CHANGED"
	ErrCodeNotConfigured     = "VM_NOT_CONFIGURED"
	ErrCodeDiscoveryFailed   = "DISCOVERY_FAILED"
	ErrCodeDiscoveryPartial  = "DISCOVERY_PARTIAL"
)

// SSHError is a structured, safe-to-display application error: Code is
// stable and machine-readable, Message is a short human-readable summary
// containing no secrets, and Err (unexported from JSON, kept for logging)
// is the original cause.
type SSHError struct {
	Code    string
	Message string
	Err     error
}

func (e *SSHError) Error() string { return e.Message }
func (e *SSHError) Unwrap() error { return e.Err }

func newSSHError(code, message string, cause error) *SSHError {
	return &SSHError{Code: code, Message: message, Err: cause}
}

// classifyConnectError turns a raw network/SSH error into a safe SSHError.
// It only ever inspects error *types* and well-known Go stdlib error
// strings (never anything derived from credential material), and always
// falls back to a generic, still-safe code rather than leaking library
// internals to the caller.
func classifyConnectError(err error) *SSHError {
	if err == nil {
		return nil
	}

	// Idempotent: a caller (e.g. RecordConnectionOutcome, which runs after
	// SSHService has already classified the error once) may pass in an
	// already-classified *SSHError. Re-running the string-matching logic
	// below against its already-friendly Message (rather than the
	// original raw error text) would lose the real classification -- e.g.
	// "SSH authentication failed." doesn't contain "unable to
	// authenticate", so it would silently fall through to the generic
	// fallback. Passing an existing *SSHError straight through avoids
	// that entirely.
	var already *SSHError
	if errors.As(err, &already) {
		return already
	}

	var hostKeyUnknown *HostKeyUnknownError
	if errors.As(err, &hostKeyUnknown) {
		return newSSHError(ErrCodeHostKeyUnknown, "Host key not yet trusted.", err)
	}
	var hostKeyChanged *HostKeyChangedError
	if errors.As(err, &hostKeyChanged) {
		return newSSHError(ErrCodeHostKeyChanged, "Host key has changed since it was last trusted.", err)
	}

	if errors.Is(err, ErrCredentialNotConfigured) {
		return newSSHError(ErrCodeNotConfigured, "SSH credential is not configured for this VM.", err)
	}
	if errors.Is(err, ErrInvalidSSHKey) || errors.Is(err, ErrPassphraseProtectedKey) {
		return newSSHError(ErrCodeInvalidCredential, err.Error(), err)
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return newSSHError(ErrCodeTimeout, "Connection timed out.", err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return newSSHError(ErrCodeTimeout, "Connection timed out.", err)
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return newSSHError(ErrCodeDNSFailure, "Could not resolve host.", err)
	}

	msg := err.Error()
	switch {
	// "connection refused" is the Linux/BSD wording; Windows' net stack
	// phrases the identical condition as "actively refused it" (e.g.
	// "connectex: No connection could be made because the target machine
	// actively refused it."). Both must classify the same way since this
	// backend can run on either OS.
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "actively refused"):
		return newSSHError(ErrCodeRefused, "Connection refused.", err)
	case strings.Contains(msg, "no route to host"), strings.Contains(msg, "network is unreachable"), strings.Contains(msg, "host is down"):
		return newSSHError(ErrCodeHostUnreachable, "Host unreachable.", err)
	case strings.Contains(msg, "unable to authenticate"), strings.Contains(msg, "permission denied"):
		return newSSHError(ErrCodeAuthFailed, "SSH authentication failed.", err)
	}

	return newSSHError(ErrCodeRefused, "Could not connect to the VM.", err)
}

// classifyDialError is classifyConnectError restricted to the TCP dial
// stage (used by HostKeyService.Trust, which runs before any SSH-level
// concept like host keys or credentials applies).
func classifyDialError(err error) *SSHError {
	return classifyConnectError(err)
}
