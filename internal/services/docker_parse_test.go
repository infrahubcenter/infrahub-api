package services

import "testing"

// --- docker version ---

func TestParseDockerVersion_WithServer(t *testing.T) {
	out := `{"Client":{"Version":"27.5.1","ApiVersion":"1.47"},"Server":{"Version":"27.5.1","ApiVersion":"1.47","Os":"linux","Arch":"amd64","KernelVersion":"6.6.0"}}`
	v, ok := ParseDockerVersion(out)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if !v.HasServer {
		t.Error("HasServer = false, want true")
	}
	if v.ServerVersion != "27.5.1" || v.APIVersion != "1.47" || v.Os != "linux" {
		t.Errorf("v = %+v", v)
	}
}

func TestParseDockerVersion_NoServer_DaemonDown(t *testing.T) {
	out := `{"Client":{"Version":"27.5.1","ApiVersion":"1.47"}}`
	v, ok := ParseDockerVersion(out)
	if !ok {
		t.Fatal("expected ok=true (client half is still valid JSON)")
	}
	if v.HasServer {
		t.Error("HasServer = true, want false when Server is absent")
	}
	if v.ClientVersion != "27.5.1" {
		t.Errorf("ClientVersion = %q", v.ClientVersion)
	}
}

func TestParseDockerVersion_Malformed(t *testing.T) {
	if _, ok := ParseDockerVersion("not json"); ok {
		t.Error("expected ok=false for malformed input")
	}
}

// --- docker info ---

func TestParseDockerInfo_Normal(t *testing.T) {
	out := `{"Driver":"overlay2","LoggingDriver":"json-file","CgroupDriver":"systemd","CgroupVersion":"2","KernelVersion":"6.6.0","OperatingSystem":"Ubuntu 22.04","Architecture":"x86_64","NCPU":16,"MemTotal":7182942208}`
	info, ok := ParseDockerInfo(out)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if info.StorageDriver != "overlay2" || info.CgroupVersion != "2" {
		t.Errorf("info = %+v", info)
	}
	if !info.NCPUOk || info.NCPU != 16 {
		t.Errorf("NCPU = %d, ok=%v", info.NCPU, info.NCPUOk)
	}
	if !info.MemTotalOk || info.MemTotal != 7182942208 {
		t.Errorf("MemTotal = %d, ok=%v", info.MemTotal, info.MemTotalOk)
	}
}

func TestParseDockerInfo_MissingFieldsNeverFabricated(t *testing.T) {
	out := `{"Driver":"overlay2"}`
	info, ok := ParseDockerInfo(out)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if info.NCPUOk {
		t.Error("NCPUOk = true, want false when NCPU is absent from the JSON")
	}
	if info.MemTotalOk {
		t.Error("MemTotalOk = true, want false when MemTotal is absent")
	}
}

// --- docker inspect (containers) ---

const sampleContainerInspect = `[
  {
    "Id": "a83f91c2b1e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0",
    "Created": "2024-01-01T00:00:00.123456789Z",
    "Path": "node",
    "Args": ["server.js"],
    "Name": "/backend-api",
    "State": {
      "Status": "running",
      "StartedAt": "2024-01-02T00:00:01Z",
      "FinishedAt": "0001-01-01T00:00:00Z",
      "Health": {"Status": "healthy"}
    },
    "RestartCount": 2,
    "Platform": "linux",
    "Image": "sha256:deadbeef00000000000000000000000000000000000000000000000000000",
    "Config": {"Image": "myrepo/api:2.4", "Cmd": ["node", "server.js"]},
    "Mounts": [{"Type":"bind","Source":"/data/backend","Destination":"/app/data","RW":true}],
    "NetworkSettings": {
      "Ports": {"8080/tcp": [{"HostIp":"0.0.0.0","HostPort":"8080"}]},
      "Networks": {"backend-network": {"IPAddress":"172.20.0.5/16","Gateway":"172.20.0.1","MacAddress":"02:42:ac:14:00:05"}}
    }
  },
  {
    "Id": "z000000000000000000000000000000000000000000000000000000000000",
    "Created": "2024-01-01T00:00:00Z",
    "Name": "/worker",
    "State": {"Status": "exited", "StartedAt": "0001-01-01T00:00:00Z", "FinishedAt": "2024-01-03T00:00:00Z"},
    "RestartCount": 12,
    "Image": "sha256:cafebabe00000000000000000000000000000000000000000000000000000",
    "Config": {"Image": "myrepo/worker:1.8"},
    "NetworkSettings": {"Ports": {}, "Networks": {}}
  }
]`

func TestParseDockerInspectContainers_Normal(t *testing.T) {
	containers := ParseDockerInspectContainers(sampleContainerInspect)
	if len(containers) != 2 {
		t.Fatalf("got %d containers, want 2", len(containers))
	}
	c := containers[0]
	if c.Name != "backend-api" {
		t.Errorf("Name = %q, want backend-api (leading / stripped)", c.Name)
	}
	if c.Status != "RUNNING" {
		t.Errorf("Status = %q, want RUNNING", c.Status)
	}
	if c.Health != "HEALTHY" {
		t.Errorf("Health = %q, want HEALTHY", c.Health)
	}
	if c.RestartCount != 2 {
		t.Errorf("RestartCount = %d, want 2", c.RestartCount)
	}
	if c.Image != "myrepo/api:2.4" {
		t.Errorf("Image = %q", c.Image)
	}
	if c.Command != "node server.js" {
		t.Errorf("Command = %q, want %q (must include the entrypoint binary from Path, not just Args)", c.Command, "node server.js")
	}
	if c.CreatedAtRemote == nil {
		t.Error("CreatedAtRemote is nil, want a parsed time")
	}
	if c.StartedAtRemote == nil {
		t.Error("StartedAtRemote is nil, want a parsed time (container is running)")
	}
}

func TestParseDockerInspectContainers_NoHealthcheck(t *testing.T) {
	containers := ParseDockerInspectContainers(sampleContainerInspect)
	worker := containers[1]
	if worker.Health != "NO_HEALTHCHECK" {
		t.Errorf("Health = %q, want NO_HEALTHCHECK (spec #12: absent healthcheck is not UNHEALTHY)", worker.Health)
	}
}

func TestParseDockerInspectContainers_ExitedHasNoStartedAt(t *testing.T) {
	containers := ParseDockerInspectContainers(sampleContainerInspect)
	worker := containers[1]
	if worker.Status != "EXITED" {
		t.Errorf("Status = %q, want EXITED", worker.Status)
	}
	if worker.StartedAtRemote != nil {
		t.Error("StartedAtRemote should be nil for a container whose StartedAt is Docker's zero-time sentinel")
	}
}

func TestParseDockerInspectContainers_Ports(t *testing.T) {
	containers := ParseDockerInspectContainers(sampleContainerInspect)
	c := containers[0]
	if len(c.Ports) != 1 {
		t.Fatalf("got %d ports, want 1", len(c.Ports))
	}
	p := c.Ports[0]
	if p.ContainerPort != 8080 || p.Protocol != "tcp" || p.HostPort != 8080 || p.HostIP != "0.0.0.0" {
		t.Errorf("port = %+v", p)
	}
}

func TestParseDockerInspectContainers_MountsSafeFieldsOnly(t *testing.T) {
	containers := ParseDockerInspectContainers(sampleContainerInspect)
	c := containers[0]
	if len(c.Mounts) != 1 {
		t.Fatalf("got %d mounts, want 1", len(c.Mounts))
	}
	m := c.Mounts[0]
	if m.Source != "/data/backend" || m.Destination != "/app/data" || m.ReadOnly {
		t.Errorf("mount = %+v", m)
	}
}

func TestParseDockerInspectContainers_NetworkMembership(t *testing.T) {
	containers := ParseDockerInspectContainers(sampleContainerInspect)
	c := containers[0]
	if len(c.Networks) != 1 {
		t.Fatalf("got %d networks, want 1", len(c.Networks))
	}
	n := c.Networks[0]
	if n.NetworkName != "backend-network" || n.IPAddress != "172.20.0.5" || n.Gateway != "172.20.0.1" {
		t.Errorf("network = %+v (IPAddress should have CIDR suffix stripped)", n)
	}
}

func TestParseDockerInspectContainers_EmptyArray(t *testing.T) {
	if containers := ParseDockerInspectContainers("[]"); len(containers) != 0 {
		t.Errorf("got %d containers, want 0", len(containers))
	}
}

func TestParseDockerInspectContainers_Malformed(t *testing.T) {
	if containers := ParseDockerInspectContainers("not json"); containers != nil {
		t.Errorf("got %v, want nil", containers)
	}
}

func TestNormalizeContainerState_UnknownFallsBackSafely(t *testing.T) {
	if got := normalizeContainerState("something-new-docker-invented"); got != "UNKNOWN" {
		t.Errorf("normalizeContainerState = %q, want UNKNOWN", got)
	}
}

// --- docker images ---

func TestParseDockerImages_Normal(t *testing.T) {
	out := `{"Repository":"nginx","Tag":"1.27","ID":"sha256:aaa","Digest":"sha256:bbb","Size":"142MB","CreatedAt":"2024-01-15 10:30:00 +0000 UTC"}
{"Repository":"nginx","Tag":"latest","ID":"sha256:aaa","Digest":"sha256:bbb","Size":"142MB","CreatedAt":"2024-01-15 10:30:00 +0000 UTC"}
`
	images := ParseDockerImages(out)
	if len(images) != 2 {
		t.Fatalf("got %d images, want 2 (same image ID, two tags -- spec #22 must not collapse these)", len(images))
	}
	if images[0].ImageID != images[1].ImageID {
		t.Error("both entries should share the same image ID")
	}
	if images[0].Tag == images[1].Tag {
		t.Error("the two entries should have different tags")
	}
	if images[0].SizeBytes != 142_000_000 {
		t.Errorf("SizeBytes = %d, want 142000000", images[0].SizeBytes)
	}
	if images[0].CreatedAtRemote == nil {
		t.Error("CreatedAtRemote is nil, want a parsed time")
	}
}

func TestParseDockerImages_UntaggedNormalized(t *testing.T) {
	out := `{"Repository":"<none>","Tag":"<none>","ID":"sha256:ccc","Digest":"<none>","Size":"10MB","CreatedAt":"2024-01-15 10:30:00 +0000 UTC"}`
	images := ParseDockerImages(out)
	if len(images) != 1 {
		t.Fatalf("got %d images, want 1", len(images))
	}
	if images[0].Digest != "" {
		t.Errorf("Digest = %q, want empty for <none>", images[0].Digest)
	}
}

func TestParseDockerImages_EmptyAndMalformed(t *testing.T) {
	if images := ParseDockerImages(""); len(images) != 0 {
		t.Errorf("got %d images, want 0", len(images))
	}
	if images := ParseDockerImages("not json\n\n"); len(images) != 0 {
		t.Errorf("got %d images, want 0 (malformed lines skipped)", len(images))
	}
}

// --- docker network inspect ---

const sampleNetworkInspect = `[
  {
    "Id": "netid1",
    "Name": "backend-network",
    "Created": "2024-01-01T00:00:00Z",
    "Scope": "local",
    "Driver": "bridge",
    "Internal": false,
    "Attachable": true,
    "IPAM": {"Config": [{"Gateway": "172.20.0.1"}]},
    "Containers": {
      "a83f91c2b1e4": {"IPv4Address": "172.20.0.5/16"}
    }
  }
]`

func TestParseDockerNetworks_Normal(t *testing.T) {
	networks := ParseDockerNetworks(sampleNetworkInspect)
	if len(networks) != 1 {
		t.Fatalf("got %d networks, want 1", len(networks))
	}
	n := networks[0]
	if n.Name != "backend-network" || n.Driver != "bridge" || !n.Attachable || n.Internal {
		t.Errorf("network = %+v", n)
	}
	if n.Gateway != "172.20.0.1" {
		t.Errorf("Gateway = %q", n.Gateway)
	}
	if len(n.Members) != 1 || n.Members[0].IPAddress != "172.20.0.5" {
		t.Errorf("Members = %+v", n.Members)
	}
}

func TestParseDockerNetworks_EmptyAndMalformed(t *testing.T) {
	if networks := ParseDockerNetworks("[]"); len(networks) != 0 {
		t.Errorf("got %d networks, want 0", len(networks))
	}
	if networks := ParseDockerNetworks("garbage"); networks != nil {
		t.Errorf("got %v, want nil", networks)
	}
}

// --- docker volume inspect ---

func TestParseDockerVolumes_Normal(t *testing.T) {
	out := `[{"CreatedAt":"2024-01-01T00:00:00Z","Driver":"local","Mountpoint":"/var/lib/docker/volumes/myvol/_data","Name":"myvol","Scope":"local"}]`
	volumes := ParseDockerVolumes(out)
	if len(volumes) != 1 {
		t.Fatalf("got %d volumes, want 1", len(volumes))
	}
	v := volumes[0]
	if v.Name != "myvol" || v.Driver != "local" || v.Mountpoint == "" {
		t.Errorf("volume = %+v", v)
	}
}

func TestParseDockerVolumes_EmptyAndMalformed(t *testing.T) {
	if volumes := ParseDockerVolumes("[]"); len(volumes) != 0 {
		t.Errorf("got %d volumes, want 0", len(volumes))
	}
	if volumes := ParseDockerVolumes("garbage"); volumes != nil {
		t.Errorf("got %v, want nil", volumes)
	}
}

// --- docker stats ---

func TestParseDockerStats_Normal(t *testing.T) {
	out := `{"Container":"a83f91c2b1e4","CPUPerc":"24.35%","MemUsage":"512MiB / 1.952GiB","MemPerc":"25.62%","NetIO":"1.2MB / 820kB","BlockIO":"320kB / 120kB","PIDs":"42"}`
	stats := ParseDockerStats(out)
	if len(stats) != 1 {
		t.Fatalf("got %d stats, want 1", len(stats))
	}
	s := stats[0]
	if s.CPUPercent != 24.35 {
		t.Errorf("CPUPercent = %v, want 24.35", s.CPUPercent)
	}
	if !s.HasMemoryLimit {
		t.Error("HasMemoryLimit = false, want true")
	}
	wantUsage := int64(512 * 1024 * 1024)
	if s.MemoryUsageBytes != wantUsage {
		t.Errorf("MemoryUsageBytes = %d, want %d", s.MemoryUsageBytes, wantUsage)
	}
	if s.PIDs != 42 {
		t.Errorf("PIDs = %d, want 42", s.PIDs)
	}
	if s.NetworkRxBytes != 1_200_000 || s.NetworkTxBytes != 820_000 {
		t.Errorf("network = rx:%d tx:%d", s.NetworkRxBytes, s.NetworkTxBytes)
	}
}

func TestParseDockerStats_NoMemoryLimit(t *testing.T) {
	// Docker's own "unlimited" sentinel value for MemUsage's limit half.
	out := `{"Container":"abc","CPUPerc":"1.00%","MemUsage":"10MiB / 9223372036854772000B","MemPerc":"0.00%","NetIO":"0B / 0B","BlockIO":"0B / 0B","PIDs":"1"}`
	stats := ParseDockerStats(out)
	if len(stats) != 1 {
		t.Fatalf("got %d stats, want 1", len(stats))
	}
	if stats[0].HasMemoryLimit {
		t.Error("HasMemoryLimit = true, want false for the sentinel 'no limit' value (spec #37: NULL, never fabricated)")
	}
}

func TestParseDockerStats_MultipleContainers(t *testing.T) {
	out := "{\"Container\":\"c1\",\"CPUPerc\":\"1%\",\"MemUsage\":\"1MB / 2MB\",\"MemPerc\":\"50%\",\"NetIO\":\"0B / 0B\",\"BlockIO\":\"0B / 0B\",\"PIDs\":\"1\"}\n" +
		"{\"Container\":\"c2\",\"CPUPerc\":\"2%\",\"MemUsage\":\"3MB / 4MB\",\"MemPerc\":\"75%\",\"NetIO\":\"0B / 0B\",\"BlockIO\":\"0B / 0B\",\"PIDs\":\"2\"}\n"
	stats := ParseDockerStats(out)
	if len(stats) != 2 {
		t.Fatalf("got %d stats, want 2", len(stats))
	}
}

func TestParseDockerStats_EmptyMeansNoRunningContainers(t *testing.T) {
	if stats := ParseDockerStats(""); len(stats) != 0 {
		t.Errorf("got %d stats, want 0", len(stats))
	}
}

func TestParseDockerStats_CPUNeverNegative(t *testing.T) {
	// A malformed/negative percent must clamp to 0, never go negative.
	out := `{"Container":"c1","CPUPerc":"-5.00%","MemUsage":"1MB / 2MB","MemPerc":"50%","NetIO":"0B / 0B","BlockIO":"0B / 0B","PIDs":"1"}`
	stats := ParseDockerStats(out)
	if len(stats) != 1 {
		t.Fatalf("got %d stats, want 1", len(stats))
	}
	if stats[0].CPUPercent < 0 {
		t.Errorf("CPUPercent = %v, want >= 0", stats[0].CPUPercent)
	}
}

// --- ParseDockerSize / ParseDockerPercent ---

func TestParseDockerSize_DecimalUnits(t *testing.T) {
	cases := map[string]int64{
		"12B": 12, "800kB": 800_000, "142MB": 142_000_000, "1.2GB": 1_200_000_000,
	}
	for input, want := range cases {
		got, ok := ParseDockerSize(input)
		if !ok || got != want {
			t.Errorf("ParseDockerSize(%q) = %d, %v, want %d, true", input, got, ok, want)
		}
	}
}

func TestParseDockerSize_BinaryUnits(t *testing.T) {
	gib := 1.952
	cases := map[string]int64{
		"512MiB": 512 * 1024 * 1024, "1.952GiB": int64(gib * 1024 * 1024 * 1024),
	}
	for input, want := range cases {
		got, ok := ParseDockerSize(input)
		if !ok || got != want {
			t.Errorf("ParseDockerSize(%q) = %d, %v, want %d, true", input, got, ok, want)
		}
	}
}

func TestParseDockerSize_ZeroAndDash(t *testing.T) {
	if v, ok := ParseDockerSize("0B"); !ok || v != 0 {
		t.Errorf("ParseDockerSize(0B) = %d, %v", v, ok)
	}
	if _, ok := ParseDockerSize("--"); ok {
		t.Error("expected ok=false for '--'")
	}
}

func TestParseDockerSize_Malformed(t *testing.T) {
	for _, s := range []string{"", "notanumber", "12XX"} {
		if _, ok := ParseDockerSize(s); ok {
			t.Errorf("ParseDockerSize(%q) = ok, want failure", s)
		}
	}
}

func TestParseDockerPercent_Normal(t *testing.T) {
	if v, ok := ParseDockerPercent("24.35%"); !ok || v != 24.35 {
		t.Errorf("got %v, %v", v, ok)
	}
}

func TestParseDockerPercent_DashMeansUnavailable(t *testing.T) {
	if _, ok := ParseDockerPercent("--"); ok {
		t.Error("expected ok=false for '--'")
	}
}

// --- ComputeDockerByteRate ---

func TestComputeDockerByteRate_Normal(t *testing.T) {
	rate, ok := ComputeDockerByteRate(1000, 2000, 10)
	if !ok || rate != 100 {
		t.Errorf("rate = %v, ok = %v, want 100, true", rate, ok)
	}
}

func TestComputeDockerByteRate_CounterResetOnRestart(t *testing.T) {
	if _, ok := ComputeDockerByteRate(5000, 100, 10); ok {
		t.Error("expected ok=false when the counter goes backwards (container restarted)")
	}
}

func TestComputeDockerByteRate_ZeroElapsed(t *testing.T) {
	if _, ok := ComputeDockerByteRate(1000, 2000, 0); ok {
		t.Error("expected ok=false for zero elapsed time")
	}
}
