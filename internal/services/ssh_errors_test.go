package services

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

// TestClassifyConnectError_Idempotent is a regression test: an
// already-classified *SSHError must pass through unchanged rather than
// being re-classified against its own (already user-friendly, no longer
// pattern-matchable) Message string. Before this fix, re-classifying
// "SSH authentication failed." lost the AUTH_FAILED code because that
// friendly text doesn't contain "unable to authenticate" -- it fell back
// to the generic SSH_CONNECTION_REFUSED/"Could not connect to the VM."
// (Discovered via manual testing against a real SSH server -- see
// docs/ssh-architecture.md.)
func TestClassifyConnectError_Idempotent(t *testing.T) {
	original := newSSHError(ErrCodeAuthFailed, "SSH authentication failed.", errors.New("unable to authenticate"))

	reclassified := classifyConnectError(original)

	if reclassified.Code != ErrCodeAuthFailed {
		t.Errorf("Code = %q, want %q (re-classification must not lose the original code)", reclassified.Code, ErrCodeAuthFailed)
	}
	if reclassified.Message != "SSH authentication failed." {
		t.Errorf("Message = %q, want unchanged", reclassified.Message)
	}
	if reclassified != original {
		t.Error("expected the exact same *SSHError instance to pass through")
	}
}

func TestClassifyConnectError_Timeout(t *testing.T) {
	err := classifyConnectError(context.DeadlineExceeded)
	if err.Code != ErrCodeTimeout {
		t.Errorf("Code = %q, want %q", err.Code, ErrCodeTimeout)
	}
}

func TestClassifyConnectError_DNSFailure(t *testing.T) {
	dnsErr := &net.DNSError{Err: "no such host", Name: "nonexistent.invalid", IsNotFound: true}
	err := classifyConnectError(dnsErr)
	if err.Code != ErrCodeDNSFailure {
		t.Errorf("Code = %q, want %q", err.Code, ErrCodeDNSFailure)
	}
}

func TestClassifyConnectError_ConnectionRefused(t *testing.T) {
	err := classifyConnectError(fmt.Errorf("dial tcp 127.0.0.1:1: connect: connection refused"))
	if err.Code != ErrCodeRefused {
		t.Errorf("Code = %q, want %q", err.Code, ErrCodeRefused)
	}
}

func TestClassifyConnectError_HostKeyUnknown(t *testing.T) {
	src := &HostKeyUnknownError{HostKeyInfo{Host: "10.0.0.1", Port: 22, Algorithm: "ssh-ed25519", Fingerprint: "SHA256:abc"}}
	err := classifyConnectError(src)
	if err.Code != ErrCodeHostKeyUnknown {
		t.Errorf("Code = %q, want %q", err.Code, ErrCodeHostKeyUnknown)
	}
	// The message must never leak into something that looks like a raw
	// error dump -- it's the fixed, safe string.
	if err.Message != "Host key not yet trusted." {
		t.Errorf("Message = %q, want the fixed safe string", err.Message)
	}
}

func TestClassifyConnectError_HostKeyChanged(t *testing.T) {
	src := &HostKeyChangedError{Host: "10.0.0.1", Port: 22, Algorithm: "ssh-ed25519", OldFingerprint: "SHA256:old", NewFingerprint: "SHA256:new"}
	err := classifyConnectError(src)
	if err.Code != ErrCodeHostKeyChanged {
		t.Errorf("Code = %q, want %q", err.Code, ErrCodeHostKeyChanged)
	}
}

func TestClassifyConnectError_NotConfigured(t *testing.T) {
	err := classifyConnectError(ErrCredentialNotConfigured)
	if err.Code != ErrCodeNotConfigured {
		t.Errorf("Code = %q, want %q", err.Code, ErrCodeNotConfigured)
	}
}

// TestClassifyConnectError_NeverLeaksRawMessage is a light guard against
// accidentally interpolating something sensitive into a classified
// message -- every code's fixed message must be one of a known-safe set,
// never derived from arbitrary error text beyond the fallback bucket
// (which is itself a fixed string).
func TestClassifyConnectError_NeverLeaksRawMessage(t *testing.T) {
	sensitiveErr := errors.New("dial failed for user with key AAAAC3NzaC1lZDI1NTE5-not-a-real-secret-but-shaped-like-one")
	err := classifyConnectError(sensitiveErr)
	if err.Message == sensitiveErr.Error() {
		t.Fatal("classified message must never be the raw underlying error text verbatim")
	}
}
