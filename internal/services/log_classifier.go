// Package services: log_classifier.go is a pure, stateless heuristic that
// buckets one log line into a severity ("how bad") and category ("what
// kind"), plus a plain-English suggested next step -- shared by Docker and
// Kubernetes Logs (search results and live-tail) so both surfaces split
// into the same Healthy/Warning/Error/Critical sections with the same
// guidance. Nothing here is stored: classification runs at read time
// against whatever text was already captured, so it applies retroactively
// to history captured before this existed, and needs no schema change or
// backfill.
//
// This is a best-effort heuristic, not a security scanner -- it exists to
// surface likely-interesting lines for a human to look at faster, not to
// make an authoritative judgment. False positives/negatives are expected
// and acceptable for that purpose.
package services

import "regexp"

type LogSeverity string

const (
	LogSeverityHealthy  LogSeverity = "HEALTHY"
	LogSeverityWarning  LogSeverity = "WARNING"
	LogSeverityError    LogSeverity = "ERROR"
	LogSeverityCritical LogSeverity = "CRITICAL"
)

// LogClassification is what ClassifyLogLine produces for one line.
type LogClassification struct {
	Severity   LogSeverity `json:"severity"`
	Category   string      `json:"category,omitempty"`
	Suggestion string      `json:"suggestion,omitempty"`
}

var healthyClassification = LogClassification{Severity: LogSeverityHealthy}

// logRule is one entry in the ordered rule list ClassifyLogLine checks --
// first match wins, so rules are ordered most-severe/most-specific first.
type logRule struct {
	pattern        *regexp.Regexp
	classification LogClassification
}

// Word-boundary-anchored, case-insensitive throughout ("(?i)") -- e.g. the
// HTTP status patterns require the digits to stand alone (`\b...\b`) so an
// incidental number like a port or a byte count doesn't false-positive as
// a status code.
var logClassificationRules = []logRule{
	{regexp.MustCompile(`(?i)\bpanic\b|\bfatal\b|segmentation fault|stack ?trace|unrecoverable`), LogClassification{
		Severity: LogSeverityCritical, Category: "CRASH",
		Suggestion: "A fatal error or panic was logged -- the process may have crashed or restarted. Check for a recent restart/OOM event and review the full stack trace for the root cause.",
	}},
	{regexp.MustCompile(`(?i)out of memory|oom[_ -]?killed|oomkilled`), LogClassification{
		Severity: LogSeverityCritical, Category: "OUT_OF_MEMORY",
		Suggestion: "An out-of-memory condition was detected -- consider raising the container/pod's memory limit or investigating a possible memory leak.",
	}},
	{regexp.MustCompile(`\b(502|503|504)\b`), LogClassification{
		Severity: LogSeverityCritical, Category: "HTTP_5XX_UNAVAILABLE",
		Suggestion: "502/503/504 detected -- the upstream/backend service is likely down, unreachable, or timing out. Check the dependent service's health, and the reverse proxy/load balancer in front of it.",
	}},
	{regexp.MustCompile(`\b500\b`), LogClassification{
		Severity: LogSeverityError, Category: "HTTP_5XX_INTERNAL",
		Suggestion: "500 Internal Server Error detected -- check the application's own error output or exception trace immediately around this line for the root cause.",
	}},
	{regexp.MustCompile(`(?i)\b(401|403)\b|unauthorized|forbidden|authentication failed|permission denied|invalid (token|credentials)`), LogClassification{
		Severity: LogSeverityError, Category: "AUTH_SECURITY",
		Suggestion: "An authentication/authorization failure was detected -- verify credentials and access rules are configured correctly. If this repeats from the same source, it may indicate a security probing or brute-force attempt worth investigating.",
	}},
	{regexp.MustCompile(`\b429\b|(?i)too many requests|rate.?limit`), LogClassification{
		Severity: LogSeverityWarning, Category: "RATE_LIMITED",
		Suggestion: "429 Too Many Requests detected -- the client may be rate-limited. Review the rate-limit threshold, or investigate whether this is abusive/unexpected traffic.",
	}},
	{regexp.MustCompile(`\b404\b`), LogClassification{
		Severity: LogSeverityError, Category: "HTTP_404_NOT_FOUND",
		Suggestion: "404 Not Found detected -- verify the requested path/route exists, check for a recent deploy that renamed or removed an endpoint, or confirm DNS/reverse-proxy routing is correct.",
	}},
	{regexp.MustCompile(`\b(400|405|406|409|410|422)\b`), LogClassification{
		Severity: LogSeverityWarning, Category: "HTTP_4XX_CLIENT",
		Suggestion: "A client-error HTTP status was detected -- check the request payload/method against what the endpoint expects.",
	}},
	{regexp.MustCompile(`(?i)connection refused|connection reset|no route to host|dial tcp.*refused`), LogClassification{
		Severity: LogSeverityError, Category: "CONNECTIVITY",
		Suggestion: "A connection failure was detected -- confirm the target service is running and reachable on the expected host/port, and check for network policy/firewall rules blocking it.",
	}},
	{regexp.MustCompile(`(?i)\btimed? ?out\b|context deadline exceeded|i/o timeout`), LogClassification{
		Severity: LogSeverityWarning, Category: "TIMEOUT",
		Suggestion: "A timeout was detected -- check network latency and the health of whatever dependency this call was waiting on.",
	}},
	{regexp.MustCompile(`(?i)\bexception\b|\btraceback\b|unhandled`), LogClassification{
		Severity: LogSeverityError, Category: "EXCEPTION",
		Suggestion: "An unhandled exception was logged -- review the surrounding trace for the specific failing call.",
	}},
	{regexp.MustCompile(`(?i)\berror\b|\bfailed\b|\bfailure\b`), LogClassification{
		Severity: LogSeverityError, Category: "GENERIC_ERROR",
		Suggestion: "An error was logged -- review the surrounding context for the specific cause.",
	}},
	{regexp.MustCompile(`(?i)\bwarn(ing)?\b|deprecated|\bretry(ing)?\b`), LogClassification{
		Severity: LogSeverityWarning, Category: "GENERIC_WARNING",
	}},
}

// ClassifyLogLine buckets one log line into Healthy/Warning/Error/Critical
// plus (for anything above Healthy) a category and a suggested next step.
// The zero value (LogSeverityHealthy, no category/suggestion) means no
// rule matched -- most ordinary INFO/DEBUG output.
func ClassifyLogLine(line string) LogClassification {
	for _, rule := range logClassificationRules {
		if rule.pattern.MatchString(line) {
			return rule.classification
		}
	}
	return healthyClassification
}

// LogSeverityCounts tallies how many lines in a set fall into each bucket.
type LogSeverityCounts struct {
	Healthy  int `json:"healthy"`
	Warning  int `json:"warning"`
	Error    int `json:"error"`
	Critical int `json:"critical"`
}

func (c *LogSeverityCounts) Add(severity LogSeverity) {
	switch severity {
	case LogSeverityWarning:
		c.Warning++
	case LogSeverityError:
		c.Error++
	case LogSeverityCritical:
		c.Critical++
	default:
		c.Healthy++
	}
}
