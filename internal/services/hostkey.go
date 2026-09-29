package services

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ssh"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/repository"
)

// HostKeyInfo is the safe (no secrets -- a public key is not sensitive)
// description of a host key, returned to the frontend so an admin can
// visually verify a fingerprint before trusting it.
type HostKeyInfo struct {
	Host        string
	Port        int
	Algorithm   string
	Fingerprint string
}

// HostKeyUnknownError means no host key has ever been trusted for this
// resource. The connection is refused -- see docs/ssh-architecture.md's
// TOFU model -- until an admin explicitly calls HostKeyService.Trust.
type HostKeyUnknownError struct {
	HostKeyInfo
}

func (e *HostKeyUnknownError) Error() string {
	return fmt.Sprintf("host key not yet trusted for %s:%d (%s %s)", e.Host, e.Port, e.Algorithm, e.Fingerprint)
}

// HostKeyChangedError means a host key was trusted previously, but the key
// presented on this connection attempt has a different fingerprint. The
// connection is refused unconditionally; nothing here ever auto-updates
// the trusted key.
type HostKeyChangedError struct {
	Host           string
	Port           int
	Algorithm      string
	OldFingerprint string
	NewFingerprint string
}

func (e *HostKeyChangedError) Error() string {
	return fmt.Sprintf("host key for %s:%d changed: trusted %s, presented %s", e.Host, e.Port, e.OldFingerprint, e.NewFingerprint)
}

// HostKeyService implements trust-on-first-use host key verification: an
// ssh.HostKeyCallback that refuses anything not already trusted, and an
// explicit Trust operation (the only thing that ever writes a trusted
// key) that independently re-dials the host to fetch its current key
// rather than trusting whatever fingerprint a client claims.
type HostKeyService struct {
	store *repository.Store
}

// NewHostKeyService creates a HostKeyService.
func NewHostKeyService(store *repository.Store) *HostKeyService {
	return &HostKeyService{store: store}
}

// VerifyCallback returns an ssh.HostKeyCallback for resourceID: it denies
// unknown or changed host keys, and updates last_verified_at on a match.
// This must be passed to every ssh.ClientConfig.HostKeyCallback in this
// codebase -- ssh.InsecureIgnoreHostKey() must never be used (Step 5 §11).
func (s *HostKeyService) VerifyCallback(ctx context.Context, resourceID uuid.UUID) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)
		algorithm := key.Type()
		host, portStr, splitErr := net.SplitHostPort(hostname)
		port := 0
		if splitErr == nil {
			port, _ = strconv.Atoi(portStr)
		} else {
			host = hostname
		}

		trusted, err := s.store.GetHostKeyByResource(ctx, resourceID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return &HostKeyUnknownError{HostKeyInfo{Host: host, Port: port, Algorithm: algorithm, Fingerprint: fingerprint}}
			}
			return fmt.Errorf("load trusted host key: %w", err)
		}

		if trusted.Fingerprint != fingerprint {
			return &HostKeyChangedError{
				Host: host, Port: port, Algorithm: algorithm,
				OldFingerprint: trusted.Fingerprint, NewFingerprint: fingerprint,
			}
		}

		_ = s.store.TouchHostKeyVerified(ctx, resourceID) // best-effort bookkeeping, never blocks the connection
		return nil
	}
}

// Trust independently connects to host:port and records whatever host key
// it presents as trusted for resourceID -- this is the one and only TOFU
// moment (Step 5 §12); it does not accept a client-supplied fingerprint,
// so a compromised frontend can't trick an admin into trusting an
// attacker's key by lying about what fingerprint was seen. It only
// performs the SSH handshake (key exchange), never authentication.
func (s *HostKeyService) Trust(ctx context.Context, resourceID uuid.UUID, host string, port int, connectTimeout time.Duration) (HostKeyInfo, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	var captured HostKeyInfo
	var capturedMarshaled string
	captureCallback := ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		captured = HostKeyInfo{Host: host, Port: port, Algorithm: key.Type(), Fingerprint: ssh.FingerprintSHA256(key)}
		capturedMarshaled = string(ssh.MarshalAuthorizedKey(key))
		return nil // accept unconditionally: this handshake's only purpose is to capture the key
	})

	dialCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return HostKeyInfo{}, classifyDialError(err)
	}
	defer conn.Close()

	sshConn, _, _, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            "vmcc-host-key-probe", // never authenticated against; the handshake fails after key exchange, which is all we need
		Auth:            nil,
		HostKeyCallback: captureCallback,
		Timeout:         connectTimeout,
	})
	if sshConn != nil {
		sshConn.Close()
	}
	// An auth failure here is expected and fine -- captureCallback already
	// ran during key exchange, before authentication was attempted. Any
	// other error (e.g. captureCallback itself failing) means we didn't
	// actually see a key.
	if captured.Fingerprint == "" {
		if err != nil {
			return HostKeyInfo{}, fmt.Errorf("connect to %s: %w", addr, err)
		}
		return HostKeyInfo{}, fmt.Errorf("no host key presented by %s", addr)
	}

	if _, err := s.store.TrustHostKey(ctx, generated.TrustHostKeyParams{
		ResourceID: resourceID, Host: host, Port: int32(port),
		Algorithm: captured.Algorithm, Fingerprint: captured.Fingerprint,
		PublicKey: capturedMarshaled,
	}); err != nil {
		return HostKeyInfo{}, fmt.Errorf("store trusted host key: %w", err)
	}

	return captured, nil
}
