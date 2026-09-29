package services

import "testing"

var testThresholds = HealthThresholds{
	CPUWarning: 80, CPUCritical: 90,
	MemoryWarning: 80, MemoryCritical: 90,
	DiskWarning: 80, DiskCritical: 90,
}

func f(v float64) *float64 { return &v }

func TestComputeSnapshotHealth_AllHealthy(t *testing.T) {
	h := ComputeSnapshotHealth(f(45), f(51), f(67), []float64{45, 44, 46}, testThresholds)
	if h != HealthHealthy {
		t.Errorf("health = %v, want HEALTHY", h)
	}
}

func TestComputeSnapshotHealth_DiskWarning(t *testing.T) {
	h := ComputeSnapshotHealth(f(20), f(30), f(85), nil, testThresholds)
	if h != HealthWarning {
		t.Errorf("health = %v, want WARNING (disk 85%% >= 80%% warning)", h)
	}
}

func TestComputeSnapshotHealth_DiskCritical(t *testing.T) {
	h := ComputeSnapshotHealth(f(20), f(30), f(95), nil, testThresholds)
	if h != HealthCritical {
		t.Errorf("health = %v, want CRITICAL (disk 95%% >= 90%% critical)", h)
	}
}

func TestComputeSnapshotHealth_MemoryCriticalDominates(t *testing.T) {
	h := ComputeSnapshotHealth(f(10), f(95), f(50), nil, testThresholds)
	if h != HealthCritical {
		t.Errorf("health = %v, want CRITICAL (worst-of across dimensions)", h)
	}
}

func TestComputeSnapshotHealth_NoMetricsIsUnknown(t *testing.T) {
	h := ComputeSnapshotHealth(nil, nil, nil, nil, testThresholds)
	if h != HealthUnknown {
		t.Errorf("health = %v, want UNKNOWN", h)
	}
}

func TestComputeSnapshotHealth_MissingDimensionIgnoredNotUnknown(t *testing.T) {
	// Only disk was collected this cycle (CPU/memory both failed) -- overall
	// health must still reflect what WAS collected, not flip to UNKNOWN.
	h := ComputeSnapshotHealth(nil, nil, f(95), nil, testThresholds)
	if h != HealthCritical {
		t.Errorf("health = %v, want CRITICAL from the one known dimension", h)
	}
}

// --- CPU spike suppression (spec #23) ---

func TestComputeSnapshotHealth_SingleCPUSpikeStaysHealthy(t *testing.T) {
	// Newest sample (95%) is a spike; the two before it were normal.
	h := ComputeSnapshotHealth(f(95), f(30), f(30), []float64{95, 20, 22}, testThresholds)
	if h != HealthHealthy {
		t.Errorf("health = %v, want HEALTHY (a single spike must not flip health, spec #23)", h)
	}
}

func TestComputeSnapshotHealth_SustainedCPUCriticalTriggers(t *testing.T) {
	// Three consecutive samples all above the critical threshold.
	h := ComputeSnapshotHealth(f(95), f(30), f(30), []float64{95, 93, 96}, testThresholds)
	if h != HealthCritical {
		t.Errorf("health = %v, want CRITICAL (3 consecutive samples over threshold)", h)
	}
}

func TestComputeSnapshotHealth_TwoConsecutiveWarningTriggers(t *testing.T) {
	h := ComputeSnapshotHealth(f(82), f(30), f(30), []float64{82, 85}, testThresholds)
	if h != HealthWarning {
		t.Errorf("health = %v, want WARNING (2 consecutive samples over warning, none reach critical)", h)
	}
}

func TestComputeSnapshotHealth_FirstEverCPUSampleNeverTriggersAlone(t *testing.T) {
	// Only one sample exists (this cycle's own) -- not enough history to
	// call anything "sustained" yet.
	h := ComputeSnapshotHealth(f(99), f(30), f(30), []float64{99}, testThresholds)
	if h != HealthHealthy {
		t.Errorf("health = %v, want HEALTHY (a lone sample is never enough to flag CPU)", h)
	}
}

// --- DeriveDisplayHealth ---

func TestDeriveDisplayHealth_NoSnapshotIsUnknown(t *testing.T) {
	if got := DeriveDisplayHealth(false, true, HealthHealthy); got != HealthUnknown {
		t.Errorf("got %v, want UNKNOWN", got)
	}
}

func TestDeriveDisplayHealth_ConnectionDownIsOffline(t *testing.T) {
	if got := DeriveDisplayHealth(true, false, HealthHealthy); got != HealthOffline {
		t.Errorf("got %v, want OFFLINE regardless of the stale stored health", got)
	}
}

func TestDeriveDisplayHealth_ConnectedUsesStoredHealth(t *testing.T) {
	if got := DeriveDisplayHealth(true, true, HealthCritical); got != HealthCritical {
		t.Errorf("got %v, want CRITICAL (connection is fine; health reflects thresholds, not connectivity -- spec #36)", got)
	}
}
