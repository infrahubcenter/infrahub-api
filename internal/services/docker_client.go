package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// DockerDaemonStatus mirrors vms.docker_daemon_status's CHECK constraint
// (migration 017). Distinct from Step 5's docker_installed boolean --
// this is re-checked independently before any Docker-specific operation
// (spec §3), never inferred from the Step 5 discovery flag.
type DockerDaemonStatus string

const (
	DockerNotInstalled     DockerDaemonStatus = "NOT_INSTALLED"
	DockerInstalled        DockerDaemonStatus = "INSTALLED" // CLI present, daemon unreachable/not running
	DockerRunning          DockerDaemonStatus = "RUNNING"
	DockerUnavailable      DockerDaemonStatus = "UNAVAILABLE"
	DockerPermissionDenied DockerDaemonStatus = "PERMISSION_DENIED"
	DockerUnknown          DockerDaemonStatus = "UNKNOWN"
)

// Fixed, backend-authored, read-only Docker CLI commands (spec §5/§30).
// Every listing command asks for structured JSON output; none of these
// strings are ever built from user input.
const (
	dockerCommandExistsCmd    = "command -v docker"
	dockerVersionCmd          = `docker version --format '{{json .}}'`
	dockerInfoCmd             = `docker info --format '{{json .}}'`
	dockerListContainerIDsCmd = "docker ps -aq"
	dockerListImagesCmd       = `docker images --digests --no-trunc --format '{{json .}}'`
	dockerListNetworkIDsCmd   = "docker network ls -q"
	dockerListVolumeNamesCmd  = "docker volume ls -q"
	dockerStatsCmd            = `docker stats --no-stream --format '{{json .}}'`
)

// DockerStatusResult is the outcome of DetectStatus: the daemon's current
// reachability plus whatever version/info detail that reachability level
// allowed collecting. Never a Go error for a normal "not installed" or
// "daemon down" outcome -- those are legitimate, common statuses, not
// failures (mirrors PackageManagerDetector.Detect's PMTypeUnsupported
// philosophy from Step 7).
type DockerStatusResult struct {
	Status  DockerDaemonStatus
	Version DockerVersionInfo
	Info    DockerInfo
}

// DockerClient wraps RemoteExecutor with Docker-CLI-specific commands and
// parsing (spec §77). No mutation command exists anywhere in this type --
// every method here only ever lists/inspects.
type DockerClient struct {
	executor       *RemoteExecutor
	commandTimeout time.Duration
}

// NewDockerClient creates a DockerClient.
func NewDockerClient(executor *RemoteExecutor, commandTimeout time.Duration) *DockerClient {
	return &DockerClient{executor: executor, commandTimeout: commandTimeout}
}

// DetectStatus determines whether Docker is installed, and if so whether
// the daemon is actually reachable by this SSH user (spec §3/§4). It
// never guesses: a status is only ever RUNNING when `docker info` itself
// succeeded, and any classification below that is based on the actual
// exit code / stderr Docker produced, never assumed from Step 5's
// docker_installed flag.
func (c *DockerClient) DetectStatus(ctx context.Context, client *ssh.Client) (DockerStatusResult, error) {
	existsRes, err := c.executor.Execute(ctx, client, dockerCommandExistsCmd, c.commandTimeout)
	if err != nil {
		return DockerStatusResult{Status: DockerUnknown}, fmt.Errorf("check docker binary: %w", err)
	}
	if existsRes.ExitCode != 0 {
		return DockerStatusResult{Status: DockerNotInstalled}, nil
	}

	verRes, err := c.executor.Execute(ctx, client, dockerVersionCmd, c.commandTimeout)
	if err != nil {
		return DockerStatusResult{Status: DockerUnknown}, fmt.Errorf("run docker version: %w", err)
	}
	// `docker version` deliberately exits nonzero when the daemon half
	// fails while still printing the client half's JSON to stdout (spec
	// §4's "CLI present, daemon down" case) -- so stdout is always parsed
	// first, before ever looking at the exit code. Gating on ExitCode != 0
	// first would discard that signal and misreport a perfectly normal
	// "daemon not running" as the vaguer UNAVAILABLE.
	version, ok := ParseDockerVersion(verRes.Stdout)
	if !ok {
		// No usable JSON at all -- fall back to exit code/stderr.
		if verRes.ExitCode != 0 {
			if isDockerPermissionError(verRes.Stderr) {
				return DockerStatusResult{Status: DockerPermissionDenied}, nil
			}
			return DockerStatusResult{Status: DockerUnavailable}, nil
		}
		return DockerStatusResult{Status: DockerUnknown}, nil
	}
	if !version.HasServer {
		// CLI present and runnable, but the daemon itself didn't respond
		// -- e.g. dockerd not started. PERMISSION_DENIED only when stderr
		// actually says so; a missing socket file is not a permission
		// problem.
		if isDockerPermissionError(verRes.Stderr) {
			return DockerStatusResult{Status: DockerPermissionDenied, Version: version}, nil
		}
		return DockerStatusResult{Status: DockerInstalled, Version: version}, nil
	}

	infoRes, err := c.executor.Execute(ctx, client, dockerInfoCmd, c.commandTimeout)
	if err != nil {
		return DockerStatusResult{Status: DockerUnknown, Version: version}, fmt.Errorf("run docker info: %w", err)
	}
	if infoRes.ExitCode != 0 {
		if isDockerPermissionError(infoRes.Stderr) {
			return DockerStatusResult{Status: DockerPermissionDenied, Version: version}, nil
		}
		return DockerStatusResult{Status: DockerUnavailable, Version: version}, nil
	}
	// A partially-populated DockerInfo (some fields absent from this
	// Docker install's output) is still a fully valid RUNNING result --
	// ParseDockerInfo's ok=false only ever happens on malformed JSON.
	info, _ := ParseDockerInfo(infoRes.Stdout)

	return DockerStatusResult{Status: DockerRunning, Version: version, Info: info}, nil
}

// GetVersion runs `docker version` on its own, for callers that already
// know the daemon is reachable and don't need the full DetectStatus
// sequence (spec §77 lists it as its own method).
func (c *DockerClient) GetVersion(ctx context.Context, client *ssh.Client) (DockerVersionInfo, error) {
	res, err := c.executor.Execute(ctx, client, dockerVersionCmd, c.commandTimeout)
	if err != nil {
		return DockerVersionInfo{}, fmt.Errorf("run docker version: %w", err)
	}
	if res.ExitCode != 0 {
		return DockerVersionInfo{}, safeCommandError("docker version", res.ExitCode, res.Stderr)
	}
	version, ok := ParseDockerVersion(res.Stdout)
	if !ok {
		return DockerVersionInfo{}, fmt.Errorf("docker version returned unparseable output")
	}
	return version, nil
}

// GetInfo runs `docker info` on its own.
func (c *DockerClient) GetInfo(ctx context.Context, client *ssh.Client) (DockerInfo, error) {
	res, err := c.executor.Execute(ctx, client, dockerInfoCmd, c.commandTimeout)
	if err != nil {
		return DockerInfo{}, fmt.Errorf("run docker info: %w", err)
	}
	if res.ExitCode != 0 {
		return DockerInfo{}, safeCommandError("docker info", res.ExitCode, res.Stderr)
	}
	info, ok := ParseDockerInfo(res.Stdout)
	if !ok {
		return DockerInfo{}, fmt.Errorf("docker info returned unparseable output")
	}
	return info, nil
}

// ListContainers returns every container (running and stopped alike --
// full inventory, spec §9) via `docker ps -aq` followed by one batched
// `docker inspect` covering every ID (never one inspect call per
// container). An empty container list is a normal, valid outcome, not an
// error -- `docker inspect` with zero arguments is itself a usage error,
// so that call is skipped entirely when there is nothing to inspect.
func (c *DockerClient) ListContainers(ctx context.Context, client *ssh.Client) ([]ContainerInfo, error) {
	idsRes, err := c.executor.Execute(ctx, client, dockerListContainerIDsCmd, c.commandTimeout)
	if err != nil {
		return nil, fmt.Errorf("list container ids: %w", err)
	}
	if idsRes.ExitCode != 0 {
		return nil, safeCommandError("docker ps -aq", idsRes.ExitCode, idsRes.Stderr)
	}
	ids := dockerHexIDTokens(idsRes.Stdout)
	if len(ids) == 0 {
		return nil, nil
	}
	inspectRes, err := c.executor.Execute(ctx, client, "docker inspect "+strings.Join(ids, " "), c.commandTimeout)
	if err != nil {
		return nil, fmt.Errorf("inspect containers: %w", err)
	}
	if inspectRes.ExitCode != 0 {
		return nil, safeCommandError("docker inspect (containers)", inspectRes.ExitCode, inspectRes.Stderr)
	}
	return ParseDockerInspectContainers(inspectRes.Stdout), nil
}

// ListImages returns every image (spec §21), one row per repository:tag
// pair -- ParseDockerImages already keeps multiple tags of the same image
// ID distinct (spec §22).
func (c *DockerClient) ListImages(ctx context.Context, client *ssh.Client) ([]ImageInfo, error) {
	res, err := c.executor.Execute(ctx, client, dockerListImagesCmd, c.commandTimeout)
	if err != nil {
		return nil, fmt.Errorf("list images: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, safeCommandError("docker images", res.ExitCode, res.Stderr)
	}
	return ParseDockerImages(res.Stdout), nil
}

// ListNetworks returns every network plus its current container
// memberships (spec §18/§19), via one batched `docker network inspect`
// covering every network ID -- the same membership data `docker
// container inspect` reports from the other side, kept in sync here
// rather than needing a second per-container membership command.
func (c *DockerClient) ListNetworks(ctx context.Context, client *ssh.Client) ([]NetworkInfo, error) {
	idsRes, err := c.executor.Execute(ctx, client, dockerListNetworkIDsCmd, c.commandTimeout)
	if err != nil {
		return nil, fmt.Errorf("list network ids: %w", err)
	}
	if idsRes.ExitCode != 0 {
		return nil, safeCommandError("docker network ls", idsRes.ExitCode, idsRes.Stderr)
	}
	ids := dockerHexIDTokens(idsRes.Stdout)
	if len(ids) == 0 {
		return nil, nil
	}
	inspectRes, err := c.executor.Execute(ctx, client, "docker network inspect "+strings.Join(ids, " "), c.commandTimeout)
	if err != nil {
		return nil, fmt.Errorf("inspect networks: %w", err)
	}
	if inspectRes.ExitCode != 0 {
		return nil, safeCommandError("docker network inspect", inspectRes.ExitCode, inspectRes.Stderr)
	}
	return ParseDockerNetworks(inspectRes.Stdout), nil
}

// ListVolumes returns every volume, via one batched `docker volume
// inspect` covering every volume name. Volume names (unlike container/
// network IDs) aren't hex, so they're validated against Docker's own
// naming character set before being placed in the command line.
func (c *DockerClient) ListVolumes(ctx context.Context, client *ssh.Client) ([]VolumeInfo, error) {
	namesRes, err := c.executor.Execute(ctx, client, dockerListVolumeNamesCmd, c.commandTimeout)
	if err != nil {
		return nil, fmt.Errorf("list volume names: %w", err)
	}
	if namesRes.ExitCode != 0 {
		return nil, safeCommandError("docker volume ls", namesRes.ExitCode, namesRes.Stderr)
	}
	names := dockerSafeNameTokens(namesRes.Stdout)
	if len(names) == 0 {
		return nil, nil
	}
	inspectRes, err := c.executor.Execute(ctx, client, "docker volume inspect "+strings.Join(names, " "), c.commandTimeout)
	if err != nil {
		return nil, fmt.Errorf("inspect volumes: %w", err)
	}
	if inspectRes.ExitCode != 0 {
		return nil, safeCommandError("docker volume inspect", inspectRes.ExitCode, inspectRes.Stderr)
	}
	return ParseDockerVolumes(inspectRes.Stdout), nil
}

// GetContainerStats runs `docker stats --no-stream` exactly once, which
// on its own reports every currently-running container on the VM (spec
// §34: this is what makes the "one SSH connection per cycle covering all
// containers" mandate possible -- no container list/loop is needed here
// at all). An empty result means no containers are currently running,
// not a failure.
func (c *DockerClient) GetContainerStats(ctx context.Context, client *ssh.Client) ([]ContainerStats, error) {
	res, err := c.executor.Execute(ctx, client, dockerStatsCmd, c.commandTimeout)
	if err != nil {
		return nil, fmt.Errorf("get container stats: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, safeCommandError("docker stats", res.ExitCode, res.Stderr)
	}
	return ParseDockerStats(res.Stdout), nil
}

// isDockerPermissionError recognizes the standard "current SSH user isn't
// in the docker group" stderr signature, so PERMISSION_DENIED can be
// reported distinctly from a generic UNAVAILABLE (spec §4). This never
// triggers an automatic privilege escalation attempt of any kind -- it
// only changes the status recorded. Deliberately narrow: a bare "dial
// unix ...: connect: no such file or directory" (the daemon simply isn't
// running -- its socket doesn't exist at all) must classify as
// UNAVAILABLE/INSTALLED, not PERMISSION_DENIED, so only the literal
// "permission denied" phrase Docker actually emits for that specific
// condition qualifies, not any connection failure that happens to
// mention the socket path.
func isDockerPermissionError(stderr string) bool {
	lower := strings.ToLower(stderr)
	signatures := []string{
		"permission denied",
		"got permission denied while trying to connect",
	}
	for _, s := range signatures {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// dockerHexIDTokens extracts one Docker ID per line from `docker ps -aq`
// / `docker network ls -q`-style output, validating each as a hex token
// before it can ever be placed into a follow-up command line -- these
// IDs come from Docker's own output rather than user input, but this
// project treats every remote-sourced value used to build a command as
// untrusted until validated, not just values that are literally
// user-supplied.
func dockerHexIDTokens(output string) []string {
	var ids []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && isDockerHexID(line) {
			ids = append(ids, line)
		}
	}
	return ids
}

func isDockerHexID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// dockerSafeNameTokens extracts one volume name per line, validated
// against Docker's own volume-naming character set.
func dockerSafeNameTokens(output string) []string {
	var names []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && isDockerSafeName(line) {
			names = append(names, line)
		}
	}
	return names
}

func isDockerSafeName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r == '_' || r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}
