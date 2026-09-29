package services

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// ConnectionTestResult is the safe, structured result of a successful
// connection test (Step 5 §16) -- never a credential, never SSH client
// internals.
type ConnectionTestResult struct {
	Host      string
	Port      int
	Username  string
	LatencyMS int64
}

// SSHService establishes SSH connections: it loads VM configuration,
// decrypts the credential just long enough to authenticate, and verifies
// the host key via HostKeyService before returning a usable client. It
// never exposes the private key or the raw *ssh.Client beyond what
// RemoteExecutor/VMDiscoveryService need internally.
type SSHService struct {
	store             *repository.Store
	sshKeyCredentials *SSHKeyCredentialService
	hostKeys          *HostKeyService
	connectTimeout    time.Duration
}

// NewSSHService creates an SSHService.
func NewSSHService(store *repository.Store, sshKeyCredentials *SSHKeyCredentialService, hostKeys *HostKeyService, connectTimeout time.Duration) *SSHService {
	return &SSHService{store: store, sshKeyCredentials: sshKeyCredentials, hostKeys: hostKeys, connectTimeout: connectTimeout}
}

// Connect resolves resourceID's stored named SSH key credential
// (vms.ssh_key_credential_id -> ssh_key_credentials) and connects with it.
// Callers must Close() the returned client. Every failure is a *SSHError
// (via classifyConnectError) -- callers should errors.As for it rather
// than string-matching. A VM with no attached credential yields
// ErrCredentialNotConfigured via the same classifyConnectError mapping a
// missing legacy credential used to produce, so no downstream
// error-handling code needs to change.
func (s *SSHService) Connect(ctx context.Context, resourceID uuid.UUID) (*ssh.Client, error) {
	vm, err := s.store.GetVMByResourceID(ctx, resourceID)
	if err != nil {
		return nil, classifyConnectError(fmt.Errorf("load vm: %w", err))
	}
	if !vm.SshKeyCredentialID.Valid {
		return nil, classifyConnectError(ErrCredentialNotConfigured)
	}
	signer, err := s.sshKeyCredentials.GetSigner(ctx, pgutil.UUID(vm.SshKeyCredentialID))
	if err != nil {
		return nil, classifyConnectError(err)
	}
	return s.connectWithSigner(ctx, vm, resourceID, signer)
}

// ConnectWithSigner is Connect's non-DB-resolved twin: it skips credential
// lookup entirely and dials with a caller-supplied signer. The only caller
// is VMConsoleHandler's ephemeral-key path -- the signer there is parsed
// once from a private key the browser sent for exactly this one session
// and is never persisted anywhere.
func (s *SSHService) ConnectWithSigner(ctx context.Context, resourceID uuid.UUID, signer ssh.Signer) (*ssh.Client, error) {
	vm, err := s.store.GetVMByResourceID(ctx, resourceID)
	if err != nil {
		return nil, classifyConnectError(fmt.Errorf("load vm: %w", err))
	}
	return s.connectWithSigner(ctx, vm, resourceID, signer)
}

func (s *SSHService) connectWithSigner(ctx context.Context, vm generated.Vm, resourceID uuid.UUID, signer ssh.Signer) (*ssh.Client, error) {
	addr := net.JoinHostPort(vm.Address, strconv.Itoa(int(vm.SshPort)))

	dialCtx, cancel := context.WithTimeout(ctx, s.connectTimeout)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, classifyConnectError(err)
	}

	clientConfig := &ssh.ClientConfig{
		User:            pgutil.TextOrEmpty(vm.Username),
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: s.hostKeys.VerifyCallback(ctx, resourceID),
		Timeout:         s.connectTimeout,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, clientConfig)
	if err != nil {
		conn.Close()
		return nil, classifyConnectError(err)
	}

	return ssh.NewClient(sshConn, chans, reqs), nil
}

// TestConnection connects, measures latency, and immediately closes the
// connection -- it establishes reachability/credential/host-key validity
// without doing anything else (Step 5 §18: "do not save monitoring
// information yet").
func (s *SSHService) TestConnection(ctx context.Context, resourceID uuid.UUID) (ConnectionTestResult, error) {
	vm, err := s.store.GetVMByResourceID(ctx, resourceID)
	if err != nil {
		return ConnectionTestResult{}, classifyConnectError(fmt.Errorf("load vm: %w", err))
	}

	start := time.Now()
	client, err := s.Connect(ctx, resourceID)
	if err != nil {
		return ConnectionTestResult{}, err
	}
	latency := time.Since(start)
	defer client.Close()

	return ConnectionTestResult{
		Host: vm.Address, Port: int(vm.SshPort), Username: pgutil.TextOrEmpty(vm.Username),
		LatencyMS: latency.Milliseconds(),
	}, nil
}

// RecordConnectionOutcome persists the result of one connection attempt
// (from TestConnection or the connect step of a discovery run) to
// vms.connection_status/last_connection_at/last_connection_error and,
// where appropriate, resources.status. Shared by both callers so the
// status-mapping rule lives in exactly one place -- see
// docs/ssh-architecture.md's connection-status/resource-status table:
//
//   - success                                  -> connection_status=CONNECTED, resources.status=ONLINE, last_seen_at updated
//   - network-level failure (timeout/refused/  -> connection_status=FAILED, resources.status=OFFLINE
//     DNS/unreachable)
//   - auth/credential/host-key problem         -> connection_status=FAILED or HOST_KEY_*, resources.status UNCHANGED
//     (the machine may well be up; nothing here claims otherwise)
func RecordConnectionOutcome(ctx context.Context, store *repository.Store, resourceID, vmRowID uuid.UUID, connErr error) error {
	if connErr == nil {
		if _, err := store.UpdateVMConnectionStatus(ctx, generated.UpdateVMConnectionStatusParams{
			ID: vmRowID, ConnectionStatus: "CONNECTED", LastConnectionError: pgutil.Text(""),
		}); err != nil {
			return fmt.Errorf("update connection status: %w", err)
		}
		if err := store.UpdateVMLastSeen(ctx, vmRowID); err != nil {
			return fmt.Errorf("update last seen: %w", err)
		}
		if _, err := store.UpdateResourceStatus(ctx, generated.UpdateResourceStatusParams{ID: resourceID, Status: "ONLINE"}); err != nil {
			return fmt.Errorf("update resource status: %w", err)
		}
		return nil
	}

	sshErr := classifyConnectError(connErr)
	connectionStatus := "FAILED"
	markOffline := false
	switch sshErr.Code {
	case ErrCodeHostKeyUnknown:
		connectionStatus = "HOST_KEY_UNKNOWN"
	case ErrCodeHostKeyChanged:
		connectionStatus = "HOST_KEY_CHANGED"
	case ErrCodeTimeout, ErrCodeRefused, ErrCodeDNSFailure, ErrCodeHostUnreachable:
		markOffline = true
	}

	if _, err := store.UpdateVMConnectionStatus(ctx, generated.UpdateVMConnectionStatusParams{
		ID: vmRowID, ConnectionStatus: connectionStatus, LastConnectionError: pgutil.Text(sshErr.Message),
	}); err != nil {
		return fmt.Errorf("update connection status: %w", err)
	}
	if markOffline {
		if _, err := store.UpdateResourceStatus(ctx, generated.UpdateResourceStatusParams{ID: resourceID, Status: "OFFLINE"}); err != nil {
			return fmt.Errorf("update resource status: %w", err)
		}
	}
	return nil
}
