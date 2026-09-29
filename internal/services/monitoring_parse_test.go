package services

import "testing"

// --- ParseProcStat / ComputeCPUUsage ---

func TestParseProcStat_Normal(t *testing.T) {
	out := "cpu  100 20 300 9000 50 5 15 10\ncpu0 50 10 150 4500 25 2 7 5\n"
	stat, ok := ParseProcStat(out)
	if !ok {
		t.Fatal("expected ok=true")
	}
	want := CPUStat{User: 100, Nice: 20, System: 300, Idle: 9000, IOWait: 50, IRQ: 5, SoftIRQ: 15, Steal: 10}
	if stat != want {
		t.Errorf("stat = %+v, want %+v", stat, want)
	}
}

func TestParseProcStat_OldKernelFewerFields(t *testing.T) {
	// Pre-2.6.24 kernels report only user/nice/system/idle.
	out := "cpu  100 20 300 9000\n"
	stat, ok := ParseProcStat(out)
	if !ok {
		t.Fatal("expected ok=true for a short but valid line")
	}
	if stat.User != 100 || stat.Idle != 9000 || stat.IOWait != 0 {
		t.Errorf("stat = %+v, want trailing fields defaulted to 0", stat)
	}
}

func TestParseProcStat_Malformed(t *testing.T) {
	cases := []string{"", "not stat output at all", "cpu  abc def ghi jkl", "cpu\n"}
	for _, c := range cases {
		if _, ok := ParseProcStat(c); ok {
			t.Errorf("ParseProcStat(%q) = ok, want failure", c)
		}
	}
}

// ComputeCPUUsage itself only ever sees two concrete samples; detecting
// "there is no previous sample yet" (spec #12's first-collection-ever
// case) is the collector's responsibility, not this function's -- it
// simply must not be called at all when no prior snapshot exists. See
// TestCollect_FirstSampleCPUIsNull in monitoring_test.go for that behavior.

func TestCountCPUCores(t *testing.T) {
	out := "cpu  100 20 300 9000 50 5 15 10\ncpu0 25 5 75 2250 12 1 3 2\ncpu1 25 5 75 2250 12 1 3 2\ncpu2 25 5 75 2250 13 1 4 3\ncpu3 25 5 75 2250 13 2 5 3\nintr 12345 0 0 0\n"
	if got := CountCPUCores(out); got != 4 {
		t.Errorf("CountCPUCores = %d, want 4", got)
	}
}

func TestCountCPUCores_SingleCore(t *testing.T) {
	out := "cpu  100 20 300 9000 50 5 15 10\ncpu0 100 20 300 9000 50 5 15 10\n"
	if got := CountCPUCores(out); got != 1 {
		t.Errorf("CountCPUCores = %d, want 1", got)
	}
}

func TestCountCPUCores_Empty(t *testing.T) {
	if got := CountCPUCores(""); got != 0 {
		t.Errorf("CountCPUCores(\"\") = %d, want 0", got)
	}
}

func TestComputeCPUUsage_NormalDelta(t *testing.T) {
	prev := CPUStat{User: 1000, Nice: 0, System: 500, Idle: 8000, IOWait: 100, IRQ: 0, SoftIRQ: 0, Steal: 0}
	curr := CPUStat{User: 1100, Nice: 0, System: 550, Idle: 8200, IOWait: 150, IRQ: 0, SoftIRQ: 0, Steal: 0}
	// total_delta = (100)+(0)+(50)+(200)+(50) = 400 ; idle_delta = 200
	usage, ok := ComputeCPUUsage(prev, curr)
	if !ok {
		t.Fatal("expected ok=true")
	}
	wantUsage := 100 * (1 - 200.0/400.0) // 50%
	if usage.UsagePercent != wantUsage {
		t.Errorf("UsagePercent = %v, want %v", usage.UsagePercent, wantUsage)
	}
	wantUser := 100 * 100.0 / 400.0 // 25%
	if usage.UserPercent != wantUser {
		t.Errorf("UserPercent = %v, want %v", usage.UserPercent, wantUser)
	}
}

func TestComputeCPUUsage_ZeroTotalDelta(t *testing.T) {
	same := CPUStat{User: 100, Idle: 900}
	if _, ok := ComputeCPUUsage(same, same); ok {
		t.Error("identical samples (zero delta) must return ok=false, not divide by zero")
	}
}

func TestComputeCPUUsage_CounterWentBackwards(t *testing.T) {
	// A counter reset (VM rebooted between samples) makes total_delta
	// negative -- must be rejected outright (ok=false), never produce a
	// negative percentage or panic on the division.
	prev := CPUStat{User: 100000, Idle: 900000}
	curr := CPUStat{User: 100, Idle: 900}
	if _, ok := ComputeCPUUsage(prev, curr); ok {
		t.Error("expected ok=false when total_delta is negative (counters reset)")
	}
}

func TestComputeCPUUsage_NeverNegativeOrOver100(t *testing.T) {
	prev := CPUStat{User: 0, Idle: 0}
	curr := CPUStat{User: 1000000, Idle: 0}
	usage, ok := ComputeCPUUsage(prev, curr)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if usage.UsagePercent != 100 {
		t.Errorf("UsagePercent = %v, want 100 (fully clamped)", usage.UsagePercent)
	}
}

// --- ParseMemInfo ---

func TestParseMemInfo_Normal(t *testing.T) {
	out := `MemTotal:       16777216 kB
MemFree:         2000000 kB
MemAvailable:    9000000 kB
SwapTotal:        2097152 kB
SwapFree:         1638400 kB
`
	m, ok := ParseMemInfo(out)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if m.TotalBytes != 16777216*1024 {
		t.Errorf("TotalBytes = %d", m.TotalBytes)
	}
	if m.UsedBytes != (16777216-9000000)*1024 {
		t.Errorf("UsedBytes = %d, want MemTotal-MemAvailable, not MemTotal-MemFree", m.UsedBytes)
	}
	if !m.HasSwap {
		t.Error("HasSwap = false, want true")
	}
	wantSwapUsed := (2097152 - 1638400) * int64(1024)
	if m.SwapUsedBytes != wantSwapUsed {
		t.Errorf("SwapUsedBytes = %d, want %d", m.SwapUsedBytes, wantSwapUsed)
	}
}

func TestParseMemInfo_NoSwap(t *testing.T) {
	out := "MemTotal:       16777216 kB\nMemAvailable:    9000000 kB\nSwapTotal:              0 kB\nSwapFree:               0 kB\n"
	m, ok := ParseMemInfo(out)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if m.HasSwap {
		t.Error("HasSwap = true for SwapTotal=0, want false (Step 6 spec #15: no swap is not a failure)")
	}
}

func TestParseMemInfo_MissingMemAvailable(t *testing.T) {
	out := "MemTotal:       16777216 kB\nMemFree:         2000000 kB\n"
	if _, ok := ParseMemInfo(out); ok {
		t.Error("expected ok=false when MemAvailable is absent -- must not fall back to MemFree")
	}
}

func TestParseMemInfo_Malformed(t *testing.T) {
	cases := []string{"", "garbage\nmore garbage", "MemTotal: not-a-number kB\n"}
	for _, c := range cases {
		if _, ok := ParseMemInfo(c); ok {
			t.Errorf("ParseMemInfo(%q) = ok, want failure", c)
		}
	}
}

func TestParseMemInfo_ExtraWhitespace(t *testing.T) {
	out := "MemTotal:        16777216   kB  \nMemAvailable:      9000000 kB\n"
	m, ok := ParseMemInfo(out)
	if !ok || m.TotalBytes != 16777216*1024 {
		t.Errorf("m=%+v ok=%v, want parsed despite irregular whitespace", m, ok)
	}
}

// --- ParseLoadAvg ---

func TestParseLoadAvg_Normal(t *testing.T) {
	one, five, fifteen, ok := ParseLoadAvg("1.42 1.12 0.87 3/512 12345\n")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if one != 1.42 || five != 1.12 || fifteen != 0.87 {
		t.Errorf("got %v %v %v", one, five, fifteen)
	}
}

func TestParseLoadAvg_ZeroValues(t *testing.T) {
	one, five, fifteen, ok := ParseLoadAvg("0.00 0.00 0.00 1/200 1\n")
	if !ok || one != 0 || five != 0 || fifteen != 0 {
		t.Errorf("got %v %v %v ok=%v", one, five, fifteen, ok)
	}
}

func TestParseLoadAvg_Malformed(t *testing.T) {
	for _, c := range []string{"", "1.42", "abc def ghi 1/1 1"} {
		if _, _, _, ok := ParseLoadAvg(c); ok {
			t.Errorf("ParseLoadAvg(%q) = ok, want failure", c)
		}
	}
}

// --- ParseUptime ---

func TestParseUptime_Normal(t *testing.T) {
	seconds, ok := ParseUptime("308522.34 1234.56\n")
	if !ok || seconds != 308522 {
		t.Errorf("seconds=%d ok=%v, want 308522", seconds, ok)
	}
}

func TestParseUptime_LargeValue(t *testing.T) {
	// ~10 years uptime, sanity check for large-number handling.
	seconds, ok := ParseUptime("315360000.00 1.00\n")
	if !ok || seconds != 315360000 {
		t.Errorf("seconds=%d ok=%v", seconds, ok)
	}
}

func TestParseUptime_Malformed(t *testing.T) {
	for _, c := range []string{"", "not-a-number", "-5.0 1.0"} {
		if _, ok := ParseUptime(c); ok {
			t.Errorf("ParseUptime(%q) = ok, want failure", c)
		}
	}
}

// --- ParseDF / FilterFilesystems ---

func TestParseDF_Normal(t *testing.T) {
	out := `Filesystem     Type  1024-blocks      Used Available Capacity Mounted on
/dev/sda1      ext4     83886080  56623104  27262976      68% /
/dev/sdb1      ext4    209715200 125829120  83886080      60% /data
tmpfs          tmpfs      524288         0    524288       0% /dev/shm
`
	entries := ParseDF(out)
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	root := entries[0]
	if root.MountPoint != "/" || root.Type != "ext4" {
		t.Errorf("root = %+v", root)
	}
	if root.TotalBytes != 83886080*1024 {
		t.Errorf("root.TotalBytes = %d", root.TotalBytes)
	}
	if root.UsagePercent != 68 {
		t.Errorf("root.UsagePercent = %v, want 68", root.UsagePercent)
	}
}

func TestParseDF_WrappedLongDeviceName(t *testing.T) {
	// A long overlay2 device name pushes df's remaining fields to the next
	// line -- a very common real-world case with Docker.
	out := `Filesystem     Type  1024-blocks      Used Available Capacity Mounted on
overlay2-2f8a9c1b4e5d6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b
               overlay   10485760   3145728   7340032     30% /var/lib/docker/overlay2/2f8a.../merged
/dev/sda1      ext4      83886080  56623104  27262976      68% /
`
	entries := ParseDF(out)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2 (wrapped line should merge into one entry)", len(entries))
	}
	if entries[0].Type != "overlay" || entries[0].UsagePercent != 30 {
		t.Errorf("wrapped entry = %+v", entries[0])
	}
}

func TestParseDF_EmptyAndMalformed(t *testing.T) {
	if entries := ParseDF(""); len(entries) != 0 {
		t.Errorf("empty input produced %d entries, want 0", len(entries))
	}
	// Header only, no data rows.
	if entries := ParseDF("Filesystem Type 1024-blocks Used Available Capacity Mounted on\n"); len(entries) != 0 {
		t.Errorf("header-only input produced %d entries, want 0", len(entries))
	}
}

func TestFilterFilesystems_DropsPseudoKeepsOverlayAndReal(t *testing.T) {
	entries := []FilesystemEntry{
		{MountPoint: "/proc", Type: "proc"},
		{MountPoint: "/sys", Type: "sysfs"},
		{MountPoint: "/dev/shm", Type: "tmpfs"},
		{MountPoint: "/", Type: "ext4"},
		{MountPoint: "/var/lib/docker/overlay2/abc/merged", Type: "overlay"},
		{MountPoint: "/data", Type: "xfs"},
	}
	filtered := FilterFilesystems(entries)
	if len(filtered) != 3 {
		t.Fatalf("got %d entries, want 3 (ext4, overlay, xfs kept)", len(filtered))
	}
	for _, f := range filtered {
		if f.Type == "proc" || f.Type == "sysfs" || f.Type == "tmpfs" {
			t.Errorf("pseudo filesystem %q was not filtered", f.Type)
		}
	}
	foundOverlay := false
	for _, f := range filtered {
		if f.Type == "overlay" {
			foundOverlay = true
		}
	}
	if !foundOverlay {
		t.Error("real Docker overlay storage was filtered out -- spec #19 explicitly forbids this")
	}
}

// --- ParseNetDev / ComputeNetworkRate ---

func TestParseNetDev_Normal(t *testing.T) {
	out := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567    1234    0    0    0     0          0         0  1234567    1234    0    0    0     0       0          0
  eth0: 987654321  654321    2    5    0     0          0        12  123456789  234567    1    3    0     0       0          0
`
	samples := ParseNetDev(out)
	if len(samples) != 1 {
		t.Fatalf("got %d samples, want 1 (lo must be dropped)", len(samples))
	}
	if samples[0].Name != "eth0" {
		t.Errorf("Name = %q, want eth0", samples[0].Name)
	}
	if samples[0].RxBytes != 987654321 || samples[0].TxBytes != 123456789 {
		t.Errorf("samples[0] = %+v", samples[0])
	}
	if samples[0].RxErrors != 2 || samples[0].TxDropped != 3 {
		t.Errorf("errors/dropped not parsed correctly: %+v", samples[0])
	}
}

func TestParseNetDev_MultipleInterfaces(t *testing.T) {
	out := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:     100       1    0    0    0     0          0         0      100       1    0    0    0     0       0          0
  eth0:  200000     200    0    0    0     0          0         0   100000     100    0    0    0     0       0          0
  ens5:  300000     300    0    0    0     0          0         0   150000     150    0    0    0     0       0          0
`
	samples := ParseNetDev(out)
	if len(samples) != 2 {
		t.Fatalf("got %d samples, want 2", len(samples))
	}
}

func TestParseNetDev_MalformedLinesSkipped(t *testing.T) {
	out := "Inter-|   Receive\n face |bytes\nnotaninterfaceline\n  eth0: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n"
	samples := ParseNetDev(out)
	if len(samples) != 1 {
		t.Fatalf("got %d samples, want 1", len(samples))
	}
}

func TestComputeNetworkRate_Normal(t *testing.T) {
	prev := NetworkInterfaceSample{RxBytes: 1000, TxBytes: 500}
	curr := NetworkInterfaceSample{RxBytes: 1000 + 60_000_000, TxBytes: 500 + 30_000_000}
	rate, ok := ComputeNetworkRate(prev, curr, 60)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if rate.RxBytesPerSec != 1_000_000 {
		t.Errorf("RxBytesPerSec = %v, want 1000000", rate.RxBytesPerSec)
	}
	if rate.TxBytesPerSec != 500_000 {
		t.Errorf("TxBytesPerSec = %v, want 500000", rate.TxBytesPerSec)
	}
}

func TestComputeNetworkRate_ZeroElapsed(t *testing.T) {
	if _, ok := ComputeNetworkRate(NetworkInterfaceSample{}, NetworkInterfaceSample{RxBytes: 100}, 0); ok {
		t.Error("expected ok=false for zero elapsed time")
	}
}

func TestComputeNetworkRate_CounterReset(t *testing.T) {
	prev := NetworkInterfaceSample{RxBytes: 1_000_000, TxBytes: 1_000_000}
	curr := NetworkInterfaceSample{RxBytes: 100, TxBytes: 100} // interface reset/replaced
	rate, ok := ComputeNetworkRate(prev, curr, 60)
	if !ok {
		t.Fatal("expected ok=true (clamped to zero, not an error)")
	}
	if rate.RxBytesPerSec != 0 || rate.TxBytesPerSec != 0 {
		t.Errorf("rate = %+v, want zero on counter reset, not negative", rate)
	}
}

// --- ParsePS ---

func TestParsePS_Normal(t *testing.T) {
	out := "Ss\nR+\nS\nS\nZ\n"
	s, ok := ParsePS(out)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if s.Total != 5 || s.Running != 1 || s.Sleeping != 3 || s.Zombie != 1 {
		t.Errorf("summary = %+v", s)
	}
}

func TestParsePS_UninterruptibleSleepCountsAsSleeping(t *testing.T) {
	s, ok := ParsePS("D\nD\nR\n")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if s.Sleeping != 2 {
		t.Errorf("Sleeping = %d, want 2 (D state)", s.Sleeping)
	}
}

func TestParsePS_Empty(t *testing.T) {
	if _, ok := ParsePS(""); ok {
		t.Error("expected ok=false for empty output")
	}
}

func TestParsePS_ExtraWhitespaceAndBlankLines(t *testing.T) {
	s, ok := ParsePS("  R+  \n\n  S \n\n")
	if !ok || s.Total != 2 {
		t.Errorf("summary=%+v ok=%v, want Total=2", s, ok)
	}
}
