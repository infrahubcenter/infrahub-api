// Package services: vm_agent_install.go holds the VM Agent's shared,
// SSH-free install info -- the published image/container name and the
// exact `docker run` command used by both the "Connect VM" flow
// (VMAgentHandler.ConnectAgentOnly) and the manual regenerate-token flow
// (VMAgentHandler.ManualInstall). There is deliberately no automated,
// SSH-based install path for the VM Agent -- this mirrors Docker Host/K8s
// Cluster exactly: name+workspace in, one-time token + docker run command
// out, nothing else. An earlier SSH-based automated installer existed
// here but was removed after it produced a misleading "Check SSH
// connectivity" error for agent-only VMs that never had SSH configured in
// the first place.
package services

import "fmt"

const (
	// vmAgentImage is the published image every install runs, verbatim --
	// see vm-agent/Dockerfile, pushed to the same docker.io/infrahubcenter
	// registry as docker-agent/k8s-agent.
	vmAgentImage         = "docker.io/infrahubcenter/infrahub-vm-agent:1.0.0"
	vmAgentContainerName = "infrahub-vm-agent"

	// vmAgentDefaultMetricsIntervalSeconds is baked into the run command
	// as INFRAHUB_METRICS_INTERVAL -- frequent enough for a "live" metrics
	// view, infrequent enough that it never competes in cost with the SSH
	// scheduler's own 60s cycle.
	vmAgentDefaultMetricsIntervalSeconds = 15
)

// VMAgentInstallService exposes the backend's own externally-reachable
// agent-connect URL, needed to build a valid `docker run` command.
type VMAgentInstallService struct {
	backendURL string
}

// NewVMAgentInstallService creates a VMAgentInstallService. backendURL is
// config.VMAgentBackendURL -- may be empty, in which case callers that
// need it (ConnectAgentOnly/ManualInstall) reject the request themselves.
func NewVMAgentInstallService(backendURL string) *VMAgentInstallService {
	return &VMAgentInstallService{backendURL: backendURL}
}

// BackendURL exposes the configured VM_AGENT_BACKEND_URL.
func (s *VMAgentInstallService) BackendURL() string {
	return s.backendURL
}

// VMAgentManualInstallSpec is the published image/container name, exposed
// for the manual-install UI.
type VMAgentManualInstallSpec struct {
	Image         string
	ContainerName string
}

// VMAgentManualInstallInfo returns VMAgentManualInstallSpec.
func VMAgentManualInstallInfo() VMAgentManualInstallSpec {
	return VMAgentManualInstallSpec{Image: vmAgentImage, ContainerName: vmAgentContainerName}
}

// VMAgentRunCommand builds the single `docker run` command that installs
// and starts the agent -- shared by ConnectAgentOnly and ManualInstall so
// the two can never drift apart. Two VM-Agent-specific mounts/env vars:
// /proc and / (read-only) for host-real metrics (no --pid=host needed --
// procfs data is host-real once bind-mounted, the same technique
// node_exporter-style host agents use), /var/log + journald's two
// standard directories for log access, and INFRAHUB_METRICS_INTERVAL for
// push cadence. Runs as root (like docker-agent's own justification for
// its socket mount: journal/log ownership varies host-to-host and can't
// be matched at build time).
//
// The / mount is a plain `:ro` bind, deliberately without a `,rslave`
// propagation flag: an earlier version added it defensively, but
// metrics_linux.go's readRootStorage only ever statfs's the mountpoint
// itself, never anything propagation would affect, and `rslave` requires
// the *source* mount to already be shared/slave -- Docker Desktop's own
// VM (WSL2 on Windows, xhyve/Virtualization.framework on Mac) doesn't
// guarantee that, so it made `docker run` itself fail outright there with
// "path / is mounted on / but it is not a shared or slave mount" (a real
// user-hit failure, not hypothetical -- keep this plain unless a real
// future need for live-propagated submounts justifies bringing it back).
func VMAgentRunCommand(backendURL, token string) string {
	return fmt.Sprintf(
		"docker run -d --name %s --restart unless-stopped "+
			"-v /proc:/host/proc:ro -v /:/host/root:ro "+
			"-v /var/log:/host/var/log:ro -v /var/log/journal:/host/var/log/journal:ro -v /run/log/journal:/host/run/log/journal:ro "+
			"-e INFRAHUB_BACKEND_URL=%s -e INFRAHUB_AGENT_TOKEN=%s -e INFRAHUB_METRICS_INTERVAL=%d %s",
		vmAgentContainerName, shellQuote(backendURL), shellQuote(token), vmAgentDefaultMetricsIntervalSeconds, vmAgentImage,
	)
}
