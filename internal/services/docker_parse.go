package services

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// This file holds every `docker` CLI output parser (Step 8 spec §78):
// pure functions from raw command stdout to typed structures, no SSH
// involved, unit-tested against fixture strings -- exactly like
// monitoring_parse.go (Step 6) and package_parse.go (Step 7). Every
// command this project runs asks Docker for structured (JSON) output
// rather than parsing a fixed-width terminal table (spec §30); several
// of Docker's own JSON fields are still human-formatted strings (sizes,
// dates) rather than raw numbers, so those specific fields still need
// parsing here -- that's a Docker CLI limitation, not a choice to parse
// pretty-printed tables.

// --- docker version --format '{{json .}}' ---

type DockerVersionInfo struct {
	ClientVersion string
	APIVersion    string
	ServerVersion string
	Os            string
	Arch          string
	KernelVersion string
	HasServer     bool // false when the daemon was unreachable but the client half still printed
}

type dockerVersionJSON struct {
	Client struct {
		Version    string `json:"Version"`
		ApiVersion string `json:"ApiVersion"`
	} `json:"Client"`
	Server *struct {
		Version       string `json:"Version"`
		ApiVersion    string `json:"ApiVersion"`
		Os            string `json:"Os"`
		Arch          string `json:"Arch"`
		KernelVersion string `json:"KernelVersion"`
	} `json:"Server"`
}

// ParseDockerVersion parses `docker version --format '{{json .}}'`. The
// Server section is a pointer because it's genuinely absent (not just
// empty) when the daemon can't be reached -- HasServer reflects that,
// letting the caller distinguish "CLI present, daemon down" from a
// fully successful read without inspecting exit codes here.
func ParseDockerVersion(output string) (DockerVersionInfo, bool) {
	var v dockerVersionJSON
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &v); err != nil {
		return DockerVersionInfo{}, false
	}
	info := DockerVersionInfo{ClientVersion: v.Client.Version, APIVersion: v.Client.ApiVersion}
	if v.Server != nil {
		info.HasServer = true
		info.ServerVersion = v.Server.Version
		if v.Server.ApiVersion != "" {
			info.APIVersion = v.Server.ApiVersion
		}
		info.Os = v.Server.Os
		info.Arch = v.Server.Arch
		info.KernelVersion = v.Server.KernelVersion
	}
	return info, true
}

// --- docker info --format '{{json .}}' ---

// DockerInfo holds only the fields spec §6 lists, and only when Docker
// actually reported them (a zero value distinguishes "not present" from
// "explicitly zero" for NCPU/MemTotal via the ok-suffixed fields).
type DockerInfo struct {
	StorageDriver   string
	LoggingDriver   string
	CgroupDriver    string
	CgroupVersion   string
	KernelVersion   string
	OperatingSystem string
	Architecture    string
	NCPU            int
	NCPUOk          bool
	MemTotal        int64
	MemTotalOk      bool
}

type dockerInfoJSON struct {
	ServerErrors    []string `json:"ServerErrors"`
	StorageDriver   string   `json:"Driver"`
	LoggingDriver   string   `json:"LoggingDriver"`
	CgroupDriver    string   `json:"CgroupDriver"`
	CgroupVersion   string   `json:"CgroupVersion"`
	KernelVersion   string   `json:"KernelVersion"`
	OperatingSystem string   `json:"OperatingSystem"`
	Architecture    string   `json:"Architecture"`
	NCPU            *int     `json:"NCPU"`
	MemTotal        *int64   `json:"MemTotal"`
}

// ParseDockerInfo parses `docker info --format '{{json .}}'`. Every field
// is optional -- a given Docker install/driver combination may not
// report all of them, and this never fabricates a value for one it
// doesn't (spec §6: "store only values actually available").
func ParseDockerInfo(output string) (DockerInfo, bool) {
	var raw dockerInfoJSON
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &raw); err != nil {
		return DockerInfo{}, false
	}
	info := DockerInfo{
		StorageDriver: raw.StorageDriver, LoggingDriver: raw.LoggingDriver,
		CgroupDriver: raw.CgroupDriver, CgroupVersion: raw.CgroupVersion,
		KernelVersion: raw.KernelVersion, OperatingSystem: raw.OperatingSystem, Architecture: raw.Architecture,
	}
	if raw.NCPU != nil {
		info.NCPU, info.NCPUOk = *raw.NCPU, true
	}
	if raw.MemTotal != nil {
		info.MemTotal, info.MemTotalOk = *raw.MemTotal, true
	}
	return info, true
}

// --- docker inspect (containers) ---

// PortMapping is one published port (spec §14). HostIP/HostPort are
// empty for a container port that isn't published to the host at all.
type PortMapping struct {
	ContainerPort int
	Protocol      string
	HostIP        string
	HostPort      int
}

// MountInfo is safe mount metadata only -- never file contents (spec §17).
type MountInfo struct {
	Source      string
	Destination string
	ReadOnly    bool
	Type        string
}

// ContainerInfo is one container's discovered detail.
type ContainerInfo struct {
	ContainerID     string
	Name            string
	Image           string // repository:tag as configured, e.g. "nginx:1.27"
	ImageID         string
	Status          string // structured enum: CREATED/RUNNING/RESTARTING/EXITED/PAUSED/DEAD/REMOVING/UNKNOWN
	State           string // Docker's raw State.Status string, kept for reference/display
	Health          string // HEALTHY/UNHEALTHY/STARTING/NO_HEALTHCHECK/UNKNOWN
	Command         string
	RestartCount    int
	Platform        string
	CreatedAtRemote *time.Time
	StartedAtRemote *time.Time
	Ports           []PortMapping
	Mounts          []MountInfo
	Networks        []ContainerNetworkInfo
}

// ContainerNetworkInfo is one network this container is attached to,
// straight from `docker inspect`'s own NetworkSettings.Networks map --
// no separate command needed for the common case.
type ContainerNetworkInfo struct {
	NetworkName string
	IPAddress   string
	Gateway     string
	MacAddress  string
}

type dockerInspectContainerJSON struct {
	Id      string `json:"Id"`
	Created string `json:"Created"`
	Path    string `json:"Path"`
	Args    []string
	Name    string `json:"Name"`
	State   struct {
		Status     string `json:"Status"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
		Health     *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	RestartCount int    `json:"RestartCount"`
	Platform     string `json:"Platform"`
	Image        string `json:"Image"` // "sha256:..." -- the image ID
	Config       struct {
		Image string   `json:"Image"` // repository:tag as configured
		Cmd   []string `json:"Cmd"`
	} `json:"Config"`
	Mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIp   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
		Networks map[string]struct {
			IPAddress  string `json:"IPAddress"`
			Gateway    string `json:"Gateway"`
			MacAddress string `json:"MacAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// ParseDockerInspectContainers parses `docker inspect <ids...>` output --
// a JSON array, one entry per container.
func ParseDockerInspectContainers(output string) []ContainerInfo {
	var raw []dockerInspectContainerJSON
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &raw); err != nil {
		return nil
	}
	containers := make([]ContainerInfo, 0, len(raw))
	for _, c := range raw {
		info := ContainerInfo{
			ContainerID:  c.Id,
			Name:         normalizeDockerName(c.Name),
			Image:        c.Config.Image,
			ImageID:      c.Image,
			Status:       normalizeContainerState(c.State.Status),
			State:        c.State.Status,
			Command:      strings.TrimSpace(strings.Join(append([]string{c.Path}, c.Args...), " ")),
			RestartCount: c.RestartCount,
			Platform:     c.Platform,
			Health:       "NO_HEALTHCHECK",
		}
		if c.State.Health != nil {
			info.Health = normalizeHealthStatus(c.State.Health.Status)
		}
		if t, ok := parseDockerTime(c.Created); ok {
			info.CreatedAtRemote = &t
		}
		if t, ok := parseDockerTime(c.State.StartedAt); ok {
			info.StartedAtRemote = &t
		}
		for portProto, bindings := range c.NetworkSettings.Ports {
			port, proto := splitPortProto(portProto)
			if len(bindings) == 0 {
				info.Ports = append(info.Ports, PortMapping{ContainerPort: port, Protocol: proto})
				continue
			}
			for _, b := range bindings {
				hostPort, _ := strconv.Atoi(b.HostPort)
				info.Ports = append(info.Ports, PortMapping{
					ContainerPort: port, Protocol: proto, HostIP: b.HostIp, HostPort: hostPort,
				})
			}
		}
		for _, m := range c.Mounts {
			info.Mounts = append(info.Mounts, MountInfo{
				Source: m.Source, Destination: m.Destination, ReadOnly: !m.RW, Type: m.Type,
			})
		}
		for name, n := range c.NetworkSettings.Networks {
			info.Networks = append(info.Networks, ContainerNetworkInfo{
				NetworkName: name, IPAddress: stripCIDR(n.IPAddress), Gateway: n.Gateway, MacAddress: n.MacAddress,
			})
		}
		containers = append(containers, info)
	}
	return containers
}

// normalizeDockerName strips Docker's leading "/" from container names
// (spec §10: normalize consistently, don't remove it "incorrectly" -- the
// leading slash is always exactly one character when present, from
// Docker's own naming convention, so a plain TrimPrefix is correct here,
// not a heuristic).
func normalizeDockerName(name string) string {
	return strings.TrimPrefix(name, "/")
}

func normalizeContainerState(status string) string {
	switch strings.ToLower(status) {
	case "created":
		return "CREATED"
	case "running":
		return "RUNNING"
	case "restarting":
		return "RESTARTING"
	case "exited":
		return "EXITED"
	case "paused":
		return "PAUSED"
	case "dead":
		return "DEAD"
	case "removing":
		return "REMOVING"
	default:
		return "UNKNOWN"
	}
}

func normalizeHealthStatus(status string) string {
	switch strings.ToLower(status) {
	case "healthy":
		return "HEALTHY"
	case "unhealthy":
		return "UNHEALTHY"
	case "starting":
		return "STARTING"
	case "":
		return "NO_HEALTHCHECK"
	default:
		return "UNKNOWN"
	}
}

// splitPortProto splits Docker's "8080/tcp" port-map key.
func splitPortProto(portProto string) (port int, proto string) {
	parts := strings.SplitN(portProto, "/", 2)
	p, _ := strconv.Atoi(parts[0])
	proto = "tcp"
	if len(parts) == 2 {
		proto = parts[1]
	}
	return p, proto
}

// stripCIDR removes a trailing "/16"-style prefix length from an IP.
func stripCIDR(ip string) string {
	if idx := strings.IndexByte(ip, '/'); idx >= 0 {
		return ip[:idx]
	}
	return ip
}

// parseDockerTime parses the RFC3339Nano-with-nanoseconds timestamps
// `docker inspect` reports (e.g. "2024-01-01T00:00:00.123456789Z"), and
// treats Docker's zero-time sentinel ("0001-01-01T00:00:00Z", used for
// "never started"/"never finished") as absent rather than a real time.
func parseDockerTime(s string) (time.Time, bool) {
	if s == "" || strings.HasPrefix(s, "0001-01-01") {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// --- docker images --digests --no-trunc --format '{{json .}}' ---

// ImageInfo is one repository:tag row -- Step 8 spec §22: multiple tags
// sharing one image ID are distinct entries here, never collapsed.
type ImageInfo struct {
	Repository      string
	Tag             string
	ImageID         string
	Digest          string
	SizeBytes       int64
	CreatedAtRemote *time.Time
}

type dockerImageLineJSON struct {
	Repository string `json:"Repository"`
	Tag        string `json:"Tag"`
	ID         string `json:"ID"`
	Digest     string `json:"Digest"`
	Size       string `json:"Size"`
	CreatedAt  string `json:"CreatedAt"`
}

// dockerImagesCreatedAtLayout matches `docker images`' CreatedAt format,
// e.g. "2024-01-15 10:30:00 +0000 UTC" -- a plain space-separated string,
// not RFC3339.
const dockerImagesCreatedAtLayout = "2006-01-02 15:04:05 -0700 MST"

// ParseDockerImages parses newline-delimited JSON, one object per image
// (one line per repository:tag, Docker's own `--format json` convention
// for `docker images` -- not a single JSON array like `inspect`).
func ParseDockerImages(output string) []ImageInfo {
	var images []ImageInfo
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var raw dockerImageLineJSON
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		img := ImageInfo{
			Repository: nonEmptyOr(raw.Repository, "<none>"),
			Tag:        nonEmptyOr(raw.Tag, "<none>"),
			ImageID:    raw.ID,
		}
		if raw.Digest != "<none>" {
			img.Digest = raw.Digest
		}
		if size, ok := ParseDockerSize(raw.Size); ok {
			img.SizeBytes = size
		}
		if t, err := time.Parse(dockerImagesCreatedAtLayout, raw.CreatedAt); err == nil {
			img.CreatedAtRemote = &t
		}
		images = append(images, img)
	}
	return images
}

// --- docker network inspect ---

// NetworkInfo is one Docker network, plus its current container
// memberships (spec §18/§19) -- `docker network inspect` reports both in
// one command, so no separate per-network membership query is needed.
type NetworkInfo struct {
	NetworkID       string
	Name            string
	Driver          string
	Scope           string
	Internal        bool
	Attachable      bool
	CreatedAtRemote *time.Time
	Gateway         string
	Members         []NetworkMember
}

type NetworkMember struct {
	ContainerID string
	IPAddress   string
}

type dockerNetworkInspectJSON struct {
	Id         string `json:"Id"`
	Name       string `json:"Name"`
	Created    string `json:"Created"`
	Scope      string `json:"Scope"`
	Driver     string `json:"Driver"`
	Internal   bool   `json:"Internal"`
	Attachable bool   `json:"Attachable"`
	IPAM       struct {
		Config []struct {
			Gateway string `json:"Gateway"`
		} `json:"Config"`
	} `json:"IPAM"`
	Containers map[string]struct {
		IPv4Address string `json:"IPv4Address"`
	} `json:"Containers"`
}

// ParseDockerNetworks parses `docker network inspect <ids...>` output.
func ParseDockerNetworks(output string) []NetworkInfo {
	var raw []dockerNetworkInspectJSON
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &raw); err != nil {
		return nil
	}
	networks := make([]NetworkInfo, 0, len(raw))
	for _, n := range raw {
		info := NetworkInfo{
			NetworkID: n.Id, Name: n.Name, Driver: n.Driver, Scope: n.Scope,
			Internal: n.Internal, Attachable: n.Attachable,
		}
		if len(n.IPAM.Config) > 0 {
			info.Gateway = n.IPAM.Config[0].Gateway
		}
		if t, ok := parseDockerTime(n.Created); ok {
			info.CreatedAtRemote = &t
		}
		for containerID, member := range n.Containers {
			info.Members = append(info.Members, NetworkMember{
				ContainerID: containerID, IPAddress: stripCIDR(member.IPv4Address),
			})
		}
		networks = append(networks, info)
	}
	return networks
}

// --- docker volume inspect ---

type VolumeInfo struct {
	Name            string
	Driver          string
	Mountpoint      string
	Scope           string
	CreatedAtRemote *time.Time
}

type dockerVolumeInspectJSON struct {
	CreatedAt  string `json:"CreatedAt"`
	Driver     string `json:"Driver"`
	Mountpoint string `json:"Mountpoint"`
	Name       string `json:"Name"`
	Scope      string `json:"Scope"`
}

// ParseDockerVolumes parses `docker volume inspect <names...>` output.
func ParseDockerVolumes(output string) []VolumeInfo {
	var raw []dockerVolumeInspectJSON
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &raw); err != nil {
		return nil
	}
	volumes := make([]VolumeInfo, 0, len(raw))
	for _, v := range raw {
		info := VolumeInfo{Name: v.Name, Driver: v.Driver, Mountpoint: v.Mountpoint, Scope: v.Scope}
		if t, ok := parseDockerTime(v.CreatedAt); ok {
			info.CreatedAtRemote = &t
		}
		volumes = append(volumes, info)
	}
	return volumes
}

// --- docker stats --no-stream --format '{{json .}}' ---

// ContainerStats is one container's point-in-time resource usage (spec
// §29/§35). CPUPercent comes straight from Docker's own calculation
// (spec §36: never recomputed from a single counter here -- `docker
// stats` already did the two-sample delta internally).
type ContainerStats struct {
	ContainerID      string
	CPUPercent       float64
	MemoryUsageBytes int64
	MemoryLimitBytes int64
	HasMemoryLimit   bool
	MemoryPercent    float64
	NetworkRxBytes   int64
	NetworkTxBytes   int64
	BlockReadBytes   int64
	BlockWriteBytes  int64
	PIDs             int
}

type dockerStatsLineJSON struct {
	Container string `json:"Container"`
	CPUPerc   string `json:"CPUPerc"`
	MemUsage  string `json:"MemUsage"`
	MemPerc   string `json:"MemPerc"`
	NetIO     string `json:"NetIO"`
	BlockIO   string `json:"BlockIO"`
	PIDs      string `json:"PIDs"`
}

// ParseDockerStats parses newline-delimited JSON from `docker stats
// --no-stream --format json` -- one line per currently-running container,
// collected in a single command covering every container on the VM at
// once (spec §34's mandatory batching).
func ParseDockerStats(output string) []ContainerStats {
	var stats []ContainerStats
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var raw dockerStatsLineJSON
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		s := ContainerStats{ContainerID: raw.Container}
		if pct, ok := ParseDockerPercent(raw.CPUPerc); ok {
			s.CPUPercent = clampPercent(pct)
		}
		if used, limit, ok := parseDockerUsagePair(raw.MemUsage); ok {
			s.MemoryUsageBytes = used
			// Docker reports an enormous sentinel limit (the cgroup's
			// effective "no limit" value, e.g. ~9223372036854771712)
			// when the container has no real memory limit -- spec §37
			// requires NULL in that case, never a fabricated percentage.
			if limit > 0 && limit < dockerNoMemoryLimitThreshold {
				s.MemoryLimitBytes = limit
				s.HasMemoryLimit = true
			}
		}
		if pct, ok := ParseDockerPercent(raw.MemPerc); ok && s.HasMemoryLimit {
			s.MemoryPercent = clampPercent(pct)
		}
		if rx, tx, ok := parseDockerUsagePair(raw.NetIO); ok {
			s.NetworkRxBytes, s.NetworkTxBytes = rx, tx
		}
		if read, write, ok := parseDockerUsagePair(raw.BlockIO); ok {
			s.BlockReadBytes, s.BlockWriteBytes = read, write
		}
		if pids, err := strconv.Atoi(strings.TrimSpace(raw.PIDs)); err == nil {
			s.PIDs = pids
		}
		stats = append(stats, s)
	}
	return stats
}

// dockerNoMemoryLimitThreshold: any reported limit at or above this is
// Docker/the kernel's "effectively unlimited" sentinel, not a real cap.
const dockerNoMemoryLimitThreshold = int64(1) << 62

// ComputeDockerByteRate turns two cumulative counter readings (network
// rx/tx, block read/write) into a bytes-per-second rate, mirroring
// ComputeNetworkRate (Step 6). docker_container_metric_snapshots stores
// only the raw cumulative counters `docker stats` reports -- rates are
// computed here, on demand, from two consecutive rows, rather than at
// collection time, so this is called from the metrics API/WebSocket
// layer, never from DockerMetricsService itself.
func ComputeDockerByteRate(prevBytes, currBytes int64, elapsedSeconds float64) (float64, bool) {
	if elapsedSeconds <= 0 {
		return 0, false
	}
	delta := currBytes - prevBytes
	if delta < 0 {
		// A counter that went backwards means the container restarted
		// (its cumulative counters reset) between samples -- no rate is
		// computable from that pair, not a negative one.
		return 0, false
	}
	return float64(delta) / elapsedSeconds, true
}

// parseDockerUsagePair parses Docker's "X<unit> / Y<unit>" pair format,
// used for MemUsage, NetIO, and BlockIO alike.
func parseDockerUsagePair(s string) (a, b int64, ok bool) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	av, aok := ParseDockerSize(strings.TrimSpace(parts[0]))
	bv, bok := ParseDockerSize(strings.TrimSpace(parts[1]))
	if !aok || !bok {
		return 0, 0, false
	}
	return av, bv, true
}

// ParseDockerPercent parses "24.35%" -> 24.35.
func ParseDockerPercent(s string) (float64, bool) {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%"))
	if s == "" || s == "--" {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// dockerSizePattern matches a Docker-formatted size like "512MiB",
// "1.95GB", "800kB", "12B".
var dockerSizePattern = regexp.MustCompile(`^([0-9.]+)\s*([A-Za-z]*)$`)

// dockerSizeUnits covers both decimal (go-units' HumanSize, used by
// `docker images`/`docker ps`) and binary (go-units' BytesSize, used by
// `docker stats`) suffixes -- this project accepts either form from any
// Docker command rather than assuming which one a given command/version
// uses.
var dockerSizeUnits = map[string]float64{
	"b":  1,
	"kb": 1000, "mb": 1000 * 1000, "gb": 1000 * 1000 * 1000, "tb": 1000 * 1000 * 1000 * 1000,
	"kib": 1024, "mib": 1024 * 1024, "gib": 1024 * 1024 * 1024, "tib": 1024 * 1024 * 1024 * 1024,
}

// ParseDockerSize parses a Docker-formatted byte size string into raw
// bytes. "0B" and "--" (Docker's own "not applicable" marker) both parse
// as 0, true.
func ParseDockerSize(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "--" || s == "" {
		return 0, false
	}
	m := dockerSizePattern.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	value, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	unit := strings.ToLower(m[2])
	if unit == "" {
		unit = "b"
	}
	multiplier, ok := dockerSizeUnits[unit]
	if !ok {
		return 0, false
	}
	return int64(value * multiplier), true
}
