// Package services: vm_agent_protocol.go defines the wire protocol
// between InfraHub's backend and the per-VM push-based VM Agent (see
// /vm-agent at the repo root) -- structurally mirrors
// docker_agent_protocol.go (JSON-over-WebSocket, agent dials out,
// authenticates with a bearer token) with one deliberate addition: this
// agent also sends metrics_push messages the backend never asked for --
// always with an empty ID, so they can never be mistaken for a reply to a
// backend-issued command (see vm_agent_hub.go's dispatch). Must stay in
// sync with the agent's own copy of this protocol (vm-agent/protocol.go).
package services

import (
	"encoding/json"
)

// VMAgentCommandType enumerates every command the backend can send to a
// connected VM Agent. Metrics never need a command -- the agent pushes
// those on its own interval (see VMAgentMsgMetricsPush) -- so these are
// logs, plus one liveness check.
type VMAgentCommandType string

const (
	VMAgentCmdFetchLogsSince VMAgentCommandType = "fetch_logs_since"
	VMAgentCmdStreamLogs     VMAgentCommandType = "stream_logs"
	VMAgentCmdStopStream     VMAgentCommandType = "stop_stream"
	// VMAgentCmdPing answers "is this agent actually alive right now" --
	// unlike metrics (pushed on the agent's own interval, so "connected"
	// alone can be up to a full interval stale) this is a synchronous
	// request/response round trip, backing the "Test Connection" button
	// (mirrors DockerAgentService.TestConnection's role for Docker
	// hosts). Answered with VMAgentPingResult.
	VMAgentCmdPing VMAgentCommandType = "ping"
)

// VMAgentCommand is one backend -> agent message.
type VMAgentCommand struct {
	ID    string             `json:"id"`
	Type  VMAgentCommandType `json:"type"`
	Since string             `json:"since,omitempty"` // RFC3339Nano; fetch_logs_since/stream_logs only
}

// VMAgentMessageType enumerates every message an agent can send back.
// MetricsPush is the one message type never sent in reply to a command --
// see the ID discipline below.
type VMAgentMessageType string

const (
	VMAgentMsgResult      VMAgentMessageType = "result"
	VMAgentMsgLogLine     VMAgentMessageType = "log_line"
	VMAgentMsgDone        VMAgentMessageType = "done"
	VMAgentMsgError       VMAgentMessageType = "error"
	VMAgentMsgMetricsPush VMAgentMessageType = "metrics_push"
)

// VMAgentMessage is one agent -> backend message. Every type except
// metrics_push carries the ID of the command it answers; metrics_push
// always carries an empty ID -- it is push telemetry, never a reply, and
// vm_agent_hub.go's dispatch checks Type before ID for exactly this
// reason (an empty-ID waiter/stream lookup would never match anyway, but
// checking Type first keeps that invariant explicit rather than
// incidental).
type VMAgentMessage struct {
	ID      string             `json:"id"`
	Type    VMAgentMessageType `json:"type"`
	Data    json.RawMessage    `json:"data,omitempty"`
	Line    string             `json:"line,omitempty"`
	Message string             `json:"message,omitempty"`
}

// VMAgentPingResult is what "ping" returns -- deliberately just a
// liveness marker, no version string: unlike the Docker/K8s agents, this
// binary has no build-time version identifier anywhere to report.
type VMAgentPingResult struct {
	Pong bool `json:"pong"`
}

// VMAgentMetricsPushData is metrics_push's payload -- one point-in-time
// sample. Field set matches monitoring_snapshots' Step 6 fields
// (migrations/007+015_vm_monitoring.sql) so the SSH-collected and
// agent-pushed series read as directly comparable in the UI. CPU% and the
// two network rates are already deltas by the time they arrive here --
// the agent computes them itself from its own in-memory previous-sample
// state (vm-agent/metrics.go), so the backend never needs raw jiffie
// counters for this source the way VMMonitoringService does for its own.
type VMAgentMetricsPushData struct {
	CPUPercent         *float64 `json:"cpu_percent,omitempty"`
	CPUCores           *int32   `json:"cpu_cores,omitempty"`
	MemoryUsedBytes    *int64   `json:"memory_used_bytes,omitempty"`
	MemoryTotalBytes   *int64   `json:"memory_total_bytes,omitempty"`
	SwapUsedBytes      *int64   `json:"swap_used_bytes,omitempty"`
	SwapTotalBytes     *int64   `json:"swap_total_bytes,omitempty"`
	Load1m             *float64 `json:"load_1m,omitempty"`
	Load5m             *float64 `json:"load_5m,omitempty"`
	Load15m            *float64 `json:"load_15m,omitempty"`
	UptimeSeconds      *int64   `json:"uptime_seconds,omitempty"`
	StorageUsedBytes   *int64   `json:"storage_used_bytes,omitempty"`
	StorageTotalBytes  *int64   `json:"storage_total_bytes,omitempty"`
	NetworkRxRateBytes *int64   `json:"network_rx_rate_bytes,omitempty"`
	NetworkTxRateBytes *int64   `json:"network_tx_rate_bytes,omitempty"`
	ProcessCount       *int32   `json:"process_count,omitempty"`
	// Host identity -- see the agent's own protocol.go doc comment for
	// why this rides along on every push instead of a separate "hello"
	// message type. Persisted as current-value columns on vms (migrations/
	// 060_vm_agent_host_identity.sql), not per-snapshot.
	Hostname      *string `json:"hostname,omitempty"`
	OS            *string `json:"os,omitempty"`
	OSVersion     *string `json:"os_version,omitempty"`
	KernelVersion *string `json:"kernel_version,omitempty"`
}
