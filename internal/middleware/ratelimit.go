package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"

	"vmcontrolcenter/backend/internal/httpx"
)

// maxTrackedRateLimitKeys bounds RateLimiter's memory: once more distinct
// keys than this are being tracked, the next Allow call does a full sweep
// removing every key with no attempts left in the current window, instead
// of growing forever as new IPs are seen (Step 20 spec: "no memory leaks").
const maxTrackedRateLimitKeys = 5000

// RateLimiter is a minimal in-memory, per-key sliding-window limiter. It
// exists specifically to slow down credential-stuffing/brute-force attempts
// against POST /api/auth/login -- not a general-purpose API gateway rate
// limiter. It deliberately has no external dependency or shared store, so
// it resets on restart and does not coordinate across multiple backend
// replicas; that is an acceptable limit for this project's single-instance
// deployment model (see docs/deployment.md), not a gap to solve here.
type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
}

// NewRateLimiter creates a RateLimiter allowing up to limit calls to
// Allow(key) within any rolling window-length interval.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{attempts: make(map[string][]time.Time), limit: limit, window: window}
}

// Allow reports whether key has made fewer than limit attempts in the
// trailing window, recording this call as an attempt either way.
func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-rl.window)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	kept := pruneBefore(rl.attempts[key], cutoff)
	allowed := len(kept) < rl.limit
	if allowed {
		kept = append(kept, now)
	}
	if len(kept) == 0 {
		delete(rl.attempts, key)
	} else {
		rl.attempts[key] = kept
	}

	if len(rl.attempts) > maxTrackedRateLimitKeys {
		rl.sweepLocked(cutoff)
	}
	return allowed
}

func pruneBefore(times []time.Time, cutoff time.Time) []time.Time {
	kept := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	return kept
}

// sweepLocked removes every tracked key whose attempts have all aged out of
// the window. Callers must hold rl.mu.
func (rl *RateLimiter) sweepLocked(cutoff time.Time) {
	for key, times := range rl.attempts {
		if kept := pruneBefore(times, cutoff); len(kept) == 0 {
			delete(rl.attempts, key)
		} else {
			rl.attempts[key] = kept
		}
	}
}

// LimitByIP rejects a request with 429 Too Many Requests once the caller's
// remote address has exceeded the limiter's configured rate, otherwise
// passes the request through unchanged.
func (rl *RateLimiter) LimitByIP(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.Allow(clientIP(r)) {
			httpx.WriteError(w, http.StatusTooManyRequests, "too many attempts, please try again later")
			return
		}
		next(w, r)
	}
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
