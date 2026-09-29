// Package services: docker_agent_protocol.go defines the wire protocol
// between InfraHub's backend and the per-VM Docker agent (see
// /docker-agent at the repo root) -- a small, stable, JSON-over-WebSocket
// command/response protocol, mirroring k8s_client.go's role exactly. The
// agent connects OUT to the backend (see docker_agent_hub.go),
// authenticates with a bearer token (docker_agent_token.go), and executes
// commands against its own local Docker Engine socket. Must stay in sync
// with the agent's own copy of this protocol (docker-agent/protocol.go).
package services

import (
	"encoding/json"
)

// DockerAgentCommandType enumerates every command the backend can send to
// a connected agent.
type DockerAgentCommandType string

const (
	DockerAgentCmdEngineVersion     DockerAgentCommandType = "engine_version"
	DockerAgentCmdListContainers    DockerAgentCommandType = "list_containers"
	DockerAgentCmdContainerStats    DockerAgentCommandType = "container_stats"
	DockerAgentCmdFetchLogsSince    DockerAgentCommandType = "fetch_logs_since"
	DockerAgentCmdStreamLogs        DockerAgentCommandType = "stream_logs"
	DockerAgentCmdStopStream        DockerAgentCommandType = "stop_stream"
	DockerAgentCmdHostResources     DockerAgentCommandType = "host_resources"
	DockerAgentCmdHostSystemMetrics DockerAgentCommandType = "host_system_metrics"
)

// DockerAgentCommand is one backend -> agent message.
type DockerAgentCommand struct {
	ID          string                 `json:"id"`
	Type        DockerAgentCommandType `json:"type"`
	ContainerID string                 `json:"container_id,omitempty"`
	Since       string                 `json:"since,omitempty"` // RFC3339Nano; fetch_logs_since/stream_logs only
}

// DockerAgentMessageType enumerates every message an agent can send back.
type DockerAgentMessageType string

const (
	DockerAgentMsgResult  DockerAgentMessageType = "result"
	DockerAgentMsgLogLine DockerAgentMessageType = "log_line"
	DockerAgentMsgDone    DockerAgentMessageType = "done"
	DockerAgentMsgError   DockerAgentMessageType = "error"
)

// DockerAgentMessage is one agent -> backend message.
type DockerAgentMessage struct {
	ID      string                 `json:"id"`
	Type    DockerAgentMessageType `json:"type"`
	Data    json.RawMessage        `json:"data,omitempty"`
	Line    string                 `json:"line,omitempty"`
	Message string                 `json:"message,omitempty"`
}

// AgentEngineVersionResult is what "engine_version" returns.
type AgentEngineVersionResult struct {
	Version    string `json:"version"`
	APIVersion string `json:"api_version"`
	OSType     string `json:"os_type"`
	Arch       string `json:"arch"`
}

// AgentContainerInfo is what "list_containers" returns, one entry per
// container -- mirrors AgentPodInfo's discipline: a small, stable,
// safe-to-serialize shape, never a raw Docker SDK type.
type AgentContainerInfo struct {
	ContainerID  string `json:"container_id"`
	Name         string `json:"name"`
	Image        string `json:"image"`
	Status       string `json:"status"`
	State        string `json:"state"`
	Health       string `json:"health,omitempty"`
	Command      string `json:"command,omitempty"`
	RestartCount int    `json:"restart_count"`
	CreatedAt    string `json:"created_at,omitempty"`
	StartedAt    string `json:"started_at,omitempty"`
}

// AgentContainerStats is what "container_stats" returns, one entry per
// currently-running container -- matches docker_parse.go's ContainerStats
// field-for-field so it's a drop-in alternate producer for the existing
// docker_container_metric_snapshots pipeline.
type AgentContainerStats struct {
	ContainerID      string  `json:"container_id"`
	CPUPercent       float64 `json:"cpu_percent"`
	MemoryUsageBytes int64   `json:"memory_usage_bytes"`
	MemoryLimitBytes int64   `json:"memory_limit_bytes"`
	HasMemoryLimit   bool    `json:"has_memory_limit"`
	MemoryPercent    float64 `json:"memory_percent"`
	NetworkRxBytes   int64   `json:"network_rx_bytes"`
	NetworkTxBytes   int64   `json:"network_tx_bytes"`
	BlockReadBytes   int64   `json:"block_read_bytes"`
	BlockWriteBytes  int64   `json:"block_write_bytes"`
	PIDs             int     `json:"pids"`
}

// AgentHostResources is what "host_resources" returns -- the Docker
// Host's full image/volume/network/build-cache inventory with storage
// sizes, mirroring docker-agent/protocol.go's HostResourcesResult
// exactly.
type AgentHostResources struct {
	Images                   []AgentImageItem      `json:"images"`
	Volumes                  []AgentVolumeItem     `json:"volumes"`
	Networks                 []AgentNetworkItem    `json:"networks"`
	BuildCache               []AgentBuildCacheItem `json:"build_cache"`
	TotalImagesSizeBytes     int64                 `json:"total_images_size_bytes"`
	TotalVolumesSizeBytes    int64                 `json:"total_volumes_size_bytes"`
	TotalBuildCacheSizeBytes int64                 `json:"total_build_cache_size_bytes"`
}

// AgentImageItem is one entry in AgentHostResources.Images.
type AgentImageItem struct {
	ID         string   `json:"id"`
	RepoTags   []string `json:"repo_tags,omitempty"`
	SizeBytes  int64    `json:"size_bytes"`
	Containers int64    `json:"containers"`
	CreatedAt  string   `json:"created_at,omitempty"`
}

// AgentVolumeItem is one entry in AgentHostResources.Volumes.
type AgentVolumeItem struct {
	Name       string `json:"name"`
	Driver     string `json:"driver"`
	Mountpoint string `json:"mountpoint,omitempty"`
	SizeBytes  *int64 `json:"size_bytes,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
}

// AgentNetworkItem is one entry in AgentHostResources.Networks.
type AgentNetworkItem struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Driver     string `json:"driver"`
	Scope      string `json:"scope"`
	Containers int    `json:"containers"`
}

// AgentBuildCacheItem is one entry in AgentHostResources.BuildCache.
type AgentBuildCacheItem struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	SizeBytes   int64  `json:"size_bytes"`
	InUse       bool   `json:"in_use"`
	Shared      bool   `json:"shared"`
	LastUsedAt  string `json:"last_used_at,omitempty"`
}

// AgentHostSystemMetrics is what "host_system_metrics" returns -- the
// Docker HOST machine's own OS-level CPU/memory/load/disk usage, mirroring
// docker-agent/protocol.go's HostSystemMetricsResult exactly. Requires the
// agent's two new bind mounts (/proc, /) added by DockerAgentRunCommand --
// an agent installed before this feature existed returns an error here
// until reinstalled with the updated run command.
type AgentHostSystemMetrics struct {
	CPUPercent         float64 `json:"cpu_percent"`
	CPUCores           int     `json:"cpu_cores"`
	MemoryTotalBytes   int64   `json:"memory_total_bytes"`
	MemoryUsedBytes    int64   `json:"memory_used_bytes"`
	LoadAvg1           float64 `json:"load_avg_1"`
	LoadAvg5           float64 `json:"load_avg_5"`
	LoadAvg15          float64 `json:"load_avg_15"`
	DiskTotalBytes     int64   `json:"disk_total_bytes"`
	DiskUsedBytes      int64   `json:"disk_used_bytes"`
	DiskAvailableBytes int64   `json:"disk_available_bytes"`
}
