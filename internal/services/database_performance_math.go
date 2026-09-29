package services

import "sort"

// SizeSample is one observed database-size measurement, used to compute a
// growth rate (spec #35-37).
type SizeSample struct {
	CapturedAtUnix int64
	SizeBytes      int64
}

// ComputeGrowthRate returns bytes/day between the first and last sample
// of a chronologically-ordered series. Requires at least two samples
// spanning a meaningful duration (an hour) -- never a rate computed from
// a single point or from samples an instant apart. The caller (not this
// function) decides whether enough days have actually accumulated to
// additionally show a 30-day projection (spec #37).
func ComputeGrowthRate(samples []SizeSample) (bytesPerDay float64, ok bool) {
	if len(samples) < 2 {
		return 0, false
	}
	first, last := samples[0], samples[len(samples)-1]
	elapsedSeconds := last.CapturedAtUnix - first.CapturedAtUnix
	if elapsedSeconds < 3600 {
		return 0, false
	}
	deltaBytes := last.SizeBytes - first.SizeBytes
	days := float64(elapsedSeconds) / 86400
	return float64(deltaBytes) / days, true
}

// minPercentileSamples is the smallest population ComputeLatencyPercentiles
// will ever compute from -- spec #104: "do not calculate percentile
// values from insufficient samples."
const minPercentileSamples = 5

// ComputeLatencyPercentiles derives p50/p95/p99 from a population of
// per-fingerprint average latencies collected in one cycle (spec #104) --
// an approximation across query fingerprints' average execution times,
// not a true per-execution latency histogram (most engines don't expose
// one), documented as such wherever it's surfaced (spec #105).
func ComputeLatencyPercentiles(values []float64) (p50, p95, p99 *float64) {
	if len(values) < minPercentileSamples {
		return nil, nil, nil
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	pick := func(p float64) *float64 {
		idx := int(p * float64(len(sorted)-1))
		v := sorted[idx]
		return &v
	}
	return pick(0.50), pick(0.95), pick(0.99)
}
