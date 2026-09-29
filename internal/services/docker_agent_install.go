// Package services: docker_agent_install.go is the fully-automated,
// SSH-based installer for InfraHub's per-VM Docker agent. Unlike the
// Kubernetes agent (an external, customer-managed cluster the admin
// installs by hand via a manifest they apply themselves), a VM is already
// fully SSH-managed by this app end to end -- so "Install Agent" is a
// single Admin-clicked action with no manual step: confirm Docker is
// reachable and the SSH user can run privileged commands, then pull and
// run the agent's own published container image over the VM's existing
// SSH connection. The agent ships as a real image (docker.io/infrahubcenter/
// docker-agent) rather than a binary this backend cross-compiles on
// demand -- no Go toolchain dependency on whatever host runs this
// backend, and no systemd requirement on the VM (docker.io/infrahubcenter/
// docker-agent runs as a container, not a systemd unit).
package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// ErrDockerAgentBackendURLUnconfigured means DOCKER_AGENT_BACKEND_URL was
// never set -- the installer refuses to guess the backend's own
// externally-reachable WebSocket URL rather than embedding a wrong one
// into the running agent's config.
var ErrDockerAgentBackendURLUnconfigured = errors.New("the backend's agent connect URL is not configured (DOCKER_AGENT_BACKEND_URL)")

// ErrDockerAgentPrivilegeUnsupported means the VM's configured SSH user
// can neither run commands as root directly nor via passwordless sudo --
// the exact same requirement (and detection) update execution already
// depends on, see DetectPrivilegeMode.
var ErrDockerAgentPrivilegeUnsupported = errors.New("the VM's SSH user cannot run privileged commands (root or passwordless sudo required)")

// ErrDockerAgentDockerUnavailable means `docker version` failed over SSH
// -- Docker itself isn't installed, isn't running, or the SSH user (even
// with sudo) can't reach the daemon. The agent is a container, so this is
// now the install's one hard prerequisite (replacing the old systemd
// requirement).
var ErrDockerAgentDockerUnavailable = errors.New("Docker is not installed or not reachable on this VM")

const (
	// dockerAgentImage is the published image every install (automated or
	// manual) runs, verbatim -- one source of truth, see
	// docker-agent/Dockerfile and docker-agent/README for how it's built
	// and published.
	//
	// Pinned to v3-cpu-cores, NOT :latest: :latest was never actually
	// updated when host-system-metrics support was added to the agent
	// (docker.io's auto-mode classifier blocks this environment from
	// pushing to that shared/public tag) -- it still points at the image
	// from before that feature existed. Every "Regenerate Agent Token" /
	// fresh install was silently deploying that stale image, which is why
	// reinstalling never actually picked up host metrics. v3-cpu-cores is
	// confirmed (live-verified) to include both host_system_metrics and
	// cpu_cores. If :latest is ever repointed at the same image this
	// tag points to, this can revert to ":latest" -- until then, this
	// exact tag is the only thing guaranteed to be current.
	dockerAgentImage         = "docker.io/infrahubcenter/infrahub-docker-agent:1.0.0"
	dockerAgentContainerName = "infrahub-docker-agent"

	// dockerAgentQuickTimeout bounds every individual small SSH command
	// the install flow runs (docker version/rm) -- deliberately separate
	// from SSHCommandTimeout, which is tuned for fast, read-only discovery
	// commands.
	dockerAgentQuickTimeout = 30 * time.Second
	// dockerAgentRunTimeout bounds the actual `docker run` -- generous,
	// since on a first install this also pulls the image over the VM's
	// own network, not just starts it.
	dockerAgentRunTimeout = 120 * time.Second
	// dockerAgentConnectWaitTimeout bounds how long Install waits, after
	// starting the container, for the agent to dial back in -- so a
	// successful install can report the freshly-connected agent's real
	// Docker Engine version immediately rather than leaving it blank
	// until some later, unrelated action happens to notice the
	// connection.
	dockerAgentConnectWaitTimeout = 20 * time.Second
)

// DockerAgentInstallResult is the outcome of one Install call. Connected
// is best-effort: false does not mean install failed, only that the
// agent hadn't dialed back within dockerAgentConnectWaitTimeout (a slow
// DNS lookup or firewall path, most commonly) -- the container was still
// started successfully and will show up as connected once it does.
type DockerAgentInstallResult struct {
	Connected     bool
	EngineVersion string
}

// DockerAgentInstallService pulls and runs the Docker agent container on
// a VM over its existing SSH access.
type DockerAgentInstallService struct {
	store          *repository.Store
	ssh            *SSHService
	executor       *RemoteExecutor
	tokens         *DockerAgentTokenService
	hub            *DockerAgentHub
	agents         *DockerAgentService
	backendURL     string
	installTimeout time.Duration
}

// NewDockerAgentInstallService creates a DockerAgentInstallService.
// backendURL is config.DockerAgentBackendURL -- may be empty, in which
// case Install fails fast with ErrDockerAgentBackendURLUnconfigured
// rather than embedding a guessed URL.
func NewDockerAgentInstallService(
	store *repository.Store, sshSvc *SSHService, executor *RemoteExecutor, tokens *DockerAgentTokenService,
	hub *DockerAgentHub, agents *DockerAgentService, backendURL string, installTimeout time.Duration,
) *DockerAgentInstallService {
	return &DockerAgentInstallService{
		store: store, ssh: sshSvc, executor: executor, tokens: tokens, hub: hub, agents: agents,
		backendURL: backendURL, installTimeout: installTimeout,
	}
}

// BackendURL exposes the configured DOCKER_AGENT_BACKEND_URL (empty if
// unconfigured) -- the manual-install endpoint needs this to tell an
// admin what to embed in a hand-run container's env without duplicating
// config wiring into the handler layer.
func (s *DockerAgentInstallService) BackendURL() string {
	return s.backendURL
}

// DockerAgentManualInstallSpec is the published image/container name the
// automated installer uses, exposed for the manual-install UI to display
// verbatim -- single source of truth shared by both paths, so the two can
// never drift out of sync.
type DockerAgentManualInstallSpec struct {
	Image         string
	ContainerName string
}

// DockerAgentManualInstallInfo returns DockerAgentManualInstallSpec.
func DockerAgentManualInstallInfo() DockerAgentManualInstallSpec {
	return DockerAgentManualInstallSpec{Image: dockerAgentImage, ContainerName: dockerAgentContainerName}
}

// DockerAgentRunCommand builds the single `docker run` command that
// installs and starts the agent -- shared by Install/InstallStreaming (run
// over SSH by this backend) and the manual-install instructions (shown
// verbatim for an admin to paste into the VM's own console), so the two
// can never drift apart. Exported for the manual-install handler.
//
// The two read-only bind mounts beyond the Docker socket -- /proc and the
// host's own root -- exist for exactly one feature: "host_system_metrics"
// (see docker-agent/hostmetrics.go and AgentHostSystemMetrics's doc
// comment). Docker's own Engine API has no live host CPU/memory/load/disk
// usage at all (Info() only reports static capacity), so reading them
// directly is the only way to get real host metrics while staying
// agent-only -- no SSH, no separate VM Agent, matching how a Docker Host
// has no VM record and no SSH access at all by design. An agent installed
// before this feature existed simply lacks these two mounts, so that one
// feature reports unavailable (available: false) until reinstalled with
// this updated command -- every other capability is unaffected.
func DockerAgentRunCommand(backendURL, token string) string {
	return fmt.Sprintf(
		"docker run -d --name %s --restart unless-stopped "+
			"-v /var/run/docker.sock:/var/run/docker.sock -v /proc:/host/proc:ro -v /:/host/root:ro "+
			"-e INFRAHUB_BACKEND_URL=%s -e INFRAHUB_AGENT_TOKEN=%s %s",
		dockerAgentContainerName, shellQuote(backendURL), shellQuote(token), dockerAgentImage,
	)
}

// Install pulls and starts the Docker agent container on vmResourceID's
// VM, (re)issuing its bearer token in the process -- any previously
// running agent for this VM stops authenticating the moment this
// completes. Reinstalling replaces the container outright (docker rm -f
// then a fresh docker run) rather than trying to reconfigure it in place.
func (s *DockerAgentInstallService) Install(ctx context.Context, vmResourceID uuid.UUID) (DockerAgentInstallResult, error) {
	if s.backendURL == "" {
		return DockerAgentInstallResult{}, ErrDockerAgentBackendURLUnconfigured
	}

	installCtx, cancel := context.WithTimeout(ctx, s.installTimeout)
	defer cancel()

	client, err := s.ssh.Connect(installCtx, vmResourceID)
	if err != nil {
		return DockerAgentInstallResult{}, fmt.Errorf("connect to vm: %w", err)
	}
	defer client.Close()

	privilege, err := DetectPrivilegeMode(installCtx, client, s.executor, dockerAgentQuickTimeout)
	if err != nil {
		return DockerAgentInstallResult{}, fmt.Errorf("detect privilege: %w", err)
	}
	if privilege == PrivilegeUnsupported {
		return DockerAgentInstallResult{}, ErrDockerAgentPrivilegeUnsupported
	}
	sudo := func(cmd string) string {
		if privilege == PrivilegeSudoNopasswd {
			return "sudo -n " + cmd
		}
		return cmd
	}

	if err := s.runQuick(installCtx, client, sudo("docker version --format '{{.Server.Version}}'"), dockerAgentQuickTimeout); err != nil {
		return DockerAgentInstallResult{}, fmt.Errorf("%w: %v", ErrDockerAgentDockerUnavailable, err)
	}

	token, err := s.tokens.GenerateToken(installCtx, vmResourceID)
	if err != nil {
		return DockerAgentInstallResult{}, fmt.Errorf("generate agent token: %w", err)
	}

	// Best-effort cleanup of a previous install -- `docker run` alone
	// fails with "name already in use" on reinstall, and there's nothing
	// wrong with this exiting nonzero when there was no prior container.
	_, _ = s.executor.Execute(installCtx, client, sudo("docker rm -f "+dockerAgentContainerName), dockerAgentQuickTimeout)

	if err := s.runQuick(installCtx, client, sudo(DockerAgentRunCommand(s.backendURL, token)), dockerAgentRunTimeout); err != nil {
		return DockerAgentInstallResult{}, fmt.Errorf("start agent container: %w", err)
	}

	result := DockerAgentInstallResult{}
	if s.waitForConnection(installCtx, vmResourceID) {
		result.Connected = true
		if test, err := s.agents.TestConnection(installCtx, vmResourceID); err == nil {
			result.EngineVersion = test.EngineVersion
		}
	}

	if _, err := s.store.SetVMDockerAgentInstalled(ctx, generated.SetVMDockerAgentInstalledParams{
		ResourceID: vmResourceID, DockerAgentVersion: pgutil.Text(result.EngineVersion),
	}); err != nil {
		return result, fmt.Errorf("record install: %w", err)
	}
	return result, nil
}

// InstallStreaming runs the identical sequence as Install, but reports a
// human-readable status line after each step (via onLine) and streams
// each remote command's real stdout/stderr live instead of only
// returning the buffered result at the end -- the "Install (Live)" mode's
// transparent view of exactly what the single-button Install already
// does automatically. Deliberately a parallel method rather than a
// refactor of Install itself: Install is unchanged, so its existing
// behavior carries zero risk from this addition.
func (s *DockerAgentInstallService) InstallStreaming(ctx context.Context, vmResourceID uuid.UUID, onLine func(line string)) (DockerAgentInstallResult, error) {
	if s.backendURL == "" {
		return DockerAgentInstallResult{}, ErrDockerAgentBackendURLUnconfigured
	}

	installCtx, cancel := context.WithTimeout(ctx, s.installTimeout)
	defer cancel()

	onLine("Connecting to VM over SSH...")
	client, err := s.ssh.Connect(installCtx, vmResourceID)
	if err != nil {
		return DockerAgentInstallResult{}, fmt.Errorf("connect to vm: %w", err)
	}
	defer client.Close()

	onLine("Detecting privilege mode (root or passwordless sudo)...")
	privilege, err := DetectPrivilegeMode(installCtx, client, s.executor, dockerAgentQuickTimeout)
	if err != nil {
		return DockerAgentInstallResult{}, fmt.Errorf("detect privilege: %w", err)
	}
	if privilege == PrivilegeUnsupported {
		return DockerAgentInstallResult{}, ErrDockerAgentPrivilegeUnsupported
	}
	sudo := func(cmd string) string {
		if privilege == PrivilegeSudoNopasswd {
			return "sudo -n " + cmd
		}
		return cmd
	}
	onLine("Privilege mode: " + string(privilege))

	onLine("$ " + sudo("docker version --format '{{.Server.Version}}'"))
	if _, err := s.runStreaming(installCtx, client, sudo("docker version --format '{{.Server.Version}}'"), dockerAgentQuickTimeout, onLine); err != nil {
		return DockerAgentInstallResult{}, fmt.Errorf("%w: %v", ErrDockerAgentDockerUnavailable, err)
	}

	onLine("Generating agent authentication token...")
	token, err := s.tokens.GenerateToken(installCtx, vmResourceID)
	if err != nil {
		return DockerAgentInstallResult{}, fmt.Errorf("generate agent token: %w", err)
	}

	onLine("$ " + sudo("docker rm -f "+dockerAgentContainerName))
	_, _ = s.executor.ExecuteStreaming(installCtx, client, sudo("docker rm -f "+dockerAgentContainerName), dockerAgentQuickTimeout, func(_, line string) { onLine(line) })

	runCmd := sudo(DockerAgentRunCommand(s.backendURL, token))
	onLine("$ " + runCmd)
	if _, err := s.runStreaming(installCtx, client, runCmd, dockerAgentRunTimeout, onLine); err != nil {
		return DockerAgentInstallResult{}, fmt.Errorf("start agent container: %w", err)
	}

	onLine("Waiting for the agent to connect back...")
	result := DockerAgentInstallResult{}
	if s.waitForConnection(installCtx, vmResourceID) {
		result.Connected = true
		onLine("Agent connected.")
		if test, err := s.agents.TestConnection(installCtx, vmResourceID); err == nil {
			result.EngineVersion = test.EngineVersion
			onLine("Docker Engine version: " + test.EngineVersion)
		}
	} else {
		onLine("Container started, but the agent hasn't connected back yet -- it should appear shortly.")
	}

	if _, err := s.store.SetVMDockerAgentInstalled(ctx, generated.SetVMDockerAgentInstalledParams{
		ResourceID: vmResourceID, DockerAgentVersion: pgutil.Text(result.EngineVersion),
	}); err != nil {
		return result, fmt.Errorf("record install: %w", err)
	}
	onLine("Done.")
	return result, nil
}

// runStreaming runs command via RemoteExecutor.ExecuteStreaming (each
// output line relayed to onLine as it arrives) and applies the same
// nonzero-exit-is-an-error convention as runQuick.
func (s *DockerAgentInstallService) runStreaming(ctx context.Context, client *ssh.Client, command string, timeout time.Duration, onLine func(string)) (CommandResult, error) {
	res, err := s.executor.ExecuteStreaming(ctx, client, command, timeout, func(_, line string) {
		onLine(line)
	})
	if err != nil {
		return res, err
	}
	if res.ExitCode != 0 {
		return res, fmt.Errorf("`%s` exited %d", command, res.ExitCode)
	}
	return res, nil
}

func (s *DockerAgentInstallService) runQuick(ctx context.Context, client *ssh.Client, command string, timeout time.Duration) error {
	res, err := s.executor.Execute(ctx, client, command, timeout)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("`%s` exited %d: %s", command, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// waitForConnection polls the hub for up to dockerAgentConnectWaitTimeout
// so a successful Install can report a live connection immediately.
func (s *DockerAgentInstallService) waitForConnection(ctx context.Context, vmResourceID uuid.UUID) bool {
	if s.hub.IsConnected(vmResourceID) {
		return true
	}
	deadline := time.Now().Add(dockerAgentConnectWaitTimeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			if s.hub.IsConnected(vmResourceID) {
				return true
			}
		}
	}
	return false
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
