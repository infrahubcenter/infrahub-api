package services

import "testing"

func TestComputeGrowthRate_TwoSamplesOverADay(t *testing.T) {
	samples := []SizeSample{
		{CapturedAtUnix: 0, SizeBytes: 48 * 1024 * 1024 * 1024},
		{CapturedAtUnix: 86400, SizeBytes: 52 * 1024 * 1024 * 1024},
	}
	rate, ok := ComputeGrowthRate(samples)
	if !ok {
		t.Fatal("expected a computable growth rate from two samples a day apart")
	}
	wantBytesPerDay := float64(4 * 1024 * 1024 * 1024)
	if rate != wantBytesPerDay {
		t.Errorf("growth rate = %v bytes/day, want %v", rate, wantBytesPerDay)
	}
}

func TestComputeGrowthRate_SingleSample_NeverComputed(t *testing.T) {
	if _, ok := ComputeGrowthRate([]SizeSample{{CapturedAtUnix: 0, SizeBytes: 100}}); ok {
		t.Error("a single sample must never produce a growth rate")
	}
}

func TestComputeGrowthRate_SamplesTooCloseTogether_NeverComputed(t *testing.T) {
	samples := []SizeSample{
		{CapturedAtUnix: 0, SizeBytes: 100},
		{CapturedAtUnix: 30, SizeBytes: 105}, // 30 seconds apart -- noise, not a rate
	}
	if _, ok := ComputeGrowthRate(samples); ok {
		t.Error("samples spread by only 30 seconds must not produce a growth rate")
	}
}

func TestComputeGrowthRate_Shrinkage_NeverClampedToZero(t *testing.T) {
	// A database can legitimately shrink (VACUUM FULL, data deletion) --
	// the rate must reflect that, never be silently floored at zero.
	samples := []SizeSample{
		{CapturedAtUnix: 0, SizeBytes: 100 * 1024 * 1024},
		{CapturedAtUnix: 86400, SizeBytes: 90 * 1024 * 1024},
	}
	rate, ok := ComputeGrowthRate(samples)
	if !ok {
		t.Fatal("expected a computable rate")
	}
	if rate >= 0 {
		t.Errorf("rate = %v, want negative (shrinkage)", rate)
	}
}

func TestComputeLatencyPercentiles_InsufficientSamples_NeverComputed(t *testing.T) {
	p50, p95, p99 := ComputeLatencyPercentiles([]float64{10, 20, 30})
	if p50 != nil || p95 != nil || p99 != nil {
		t.Error("fewer than minPercentileSamples values must never produce a percentile (spec #104)")
	}
}

func TestComputeLatencyPercentiles_SufficientSamples(t *testing.T) {
	values := []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	p50, p95, p99 := ComputeLatencyPercentiles(values)
	if p50 == nil || p95 == nil || p99 == nil {
		t.Fatal("expected computed percentiles with 10 samples")
	}
	if *p50 > *p95 || *p95 > *p99 {
		t.Errorf("percentiles out of order: p50=%v p95=%v p99=%v", *p50, *p95, *p99)
	}
}
