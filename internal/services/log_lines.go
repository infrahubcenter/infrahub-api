// Package services: log_lines.go is the one shared piece between
// docker_log_capture.go and k8s_log_capture.go -- both `docker logs
// --timestamps` and Kubernetes' GetLogs(Timestamps: true) happen to emit
// the exact same wire format (an RFC3339Nano timestamp, a space, then the
// line itself), so the parsing/truncation/sanitization logic lives here
// once instead of twice.
package services

import (
	"strings"
	"time"
	"unicode/utf8"
)

// maxCapturedLogLineRunes bounds a single captured log line's stored
// length -- a defensive cap against a pathological single line (e.g. a
// buggy app dumping a huge blob on one line), never expected to trigger
// for ordinary log output. Bounded by rune count (not raw bytes) so
// truncation can never split a multi-byte character and produce invalid
// UTF-8.
const maxCapturedLogLineRunes = 4096

type capturedLogLine struct {
	LoggedAt time.Time
	Text     string
}

// parseTimestampedLogLines splits `--timestamps`-style output into
// (timestamp, text) pairs, keeping only lines strictly after `after` (the
// previous capture's cursor) -- so a boundary line already captured last
// cycle is never captured again, regardless of whether the underlying
// --since/SinceTime cutoff the caller used is itself inclusive or
// exclusive. Returns the parsed lines (oldest first) and the latest
// timestamp seen (the zero time if none), which becomes the next cursor.
func parseTimestampedLogLines(output string, after time.Time) (lines []capturedLogLine, latest time.Time) {
	for _, raw := range strings.Split(output, "\n") {
		raw = strings.TrimRight(raw, "\r")
		if raw == "" {
			continue
		}
		idx := strings.IndexByte(raw, ' ')
		if idx < 0 {
			continue // no timestamp prefix -- can't place this line in time, skip it
		}
		ts, err := time.Parse(time.RFC3339Nano, raw[:idx])
		if err != nil {
			continue
		}
		if !ts.After(after) {
			continue
		}
		text := sanitizeCapturedLine(raw[idx+1:])
		lines = append(lines, capturedLogLine{LoggedAt: ts, Text: text})
		if ts.After(latest) {
			latest = ts
		}
	}
	return lines, latest
}

// ParsedLogLine is capturedLogLine's exported counterpart, for callers
// outside this package that need per-line timestamps without persisting a
// docker_container_log_lines row (the live-only VM Agent "recent logs"
// endpoint -- see handlers/vm_agent_logs.go's RecentLogs).
type ParsedLogLine struct {
	LoggedAt time.Time
	Text     string
}

// ParseTimestampedLogLines is parseTimestampedLogLines's exported form.
func ParseTimestampedLogLines(output string, after time.Time) ([]ParsedLogLine, time.Time) {
	lines, latest := parseTimestampedLogLines(output, after)
	out := make([]ParsedLogLine, len(lines))
	for i, l := range lines {
		out[i] = ParsedLogLine{LoggedAt: l.LoggedAt, Text: l.Text}
	}
	return out, latest
}

// sanitizeCapturedLine guarantees a value Postgres' text type will always
// accept: invalid UTF-8 (a misbehaving process writing raw binary to
// stdout) is replaced rather than left to fail the INSERT, and the result
// is truncated at a rune boundary.
func sanitizeCapturedLine(s string) string {
	s = strings.ToValidUTF8(s, "�")
	if utf8.RuneCountInString(s) <= maxCapturedLogLineRunes {
		return s
	}
	r := []rune(s)
	return string(r[:maxCapturedLogLineRunes])
}
