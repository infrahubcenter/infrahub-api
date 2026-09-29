// Package handlers: log_search.go is the one shared piece between
// docker_logs.go's and k8s_logs.go's Search/Stream handlers -- both now
// classify every line (services.ClassifyLogLine) into a severity/category/
// suggestion at read time, so the shape and the classification-scan
// helpers live here once instead of twice.
package handlers

import (
	"strings"
	"time"

	"vmcontrolcenter/backend/internal/services"
)

// logSearchLineDTO is the shared log line shape returned by both Docker's
// and Kubernetes' Logs Search endpoints.
type logSearchLineDTO struct {
	ID         string `json:"id"`
	LoggedAt   string `json:"logged_at"`
	Line       string `json:"line"`
	Severity   string `json:"severity"`
	Category   string `json:"category,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
}

func toLogSearchLineDTO(id string, loggedAt time.Time, line string) logSearchLineDTO {
	c := services.ClassifyLogLine(line)
	return logSearchLineDTO{
		ID: id, LoggedAt: loggedAt.Format(time.RFC3339Nano), Line: line,
		Severity: string(c.Severity), Category: c.Category, Suggestion: c.Suggestion,
	}
}

// logSeverityScanCap bounds how many of the most recent lines (matching
// the caller's q/time-range filters) severity filtering and the
// Healthy/Warning/Error/Critical summary counts are computed over. This is
// a heuristic, human-facing feature, not an exact aggregate over the whole
// retention window -- capping it keeps every search request cheap
// regardless of how much history a busy container/pod has accumulated.
const logSeverityScanCap int32 = 5000

// parseLogSeverityFilter validates the optional ?severity= query param.
func parseLogSeverityFilter(raw string) (services.LogSeverity, bool) {
	switch services.LogSeverity(strings.ToUpper(strings.TrimSpace(raw))) {
	case services.LogSeverityHealthy:
		return services.LogSeverityHealthy, true
	case services.LogSeverityWarning:
		return services.LogSeverityWarning, true
	case services.LogSeverityError:
		return services.LogSeverityError, true
	case services.LogSeverityCritical:
		return services.LogSeverityCritical, true
	default:
		return "", false
	}
}

// paginateClassifiedLines applies limit/offset to an already-classified,
// already-severity-filtered slice, the same way the database's LIMIT/OFFSET
// would -- used for the severity-filtered path, where filtering has to
// happen in Go after classification rather than in SQL.
func paginateClassifiedLines(lines []logSearchLineDTO, limit, offset int32) []logSearchLineDTO {
	start := int(offset)
	if start > len(lines) {
		start = len(lines)
	}
	end := start + int(limit)
	if end > len(lines) {
		end = len(lines)
	}
	page := lines[start:end]
	if page == nil {
		page = []logSearchLineDTO{}
	}
	return page
}
