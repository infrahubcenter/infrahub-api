package services

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// Step 13 spec #9: a safe, generic normalization/fingerprint utility --
// NOT a full SQL parser, and never guaranteed to normalize every SQL
// dialect perfectly. This is the fallback path used when an engine has no
// better native mechanism; PostgreSQL and MySQL/MariaDB prefer their own
// already-normalized identifiers instead (pg_stat_statements' queryid,
// performance_schema's DIGEST) since those are computed by the engine's
// own parser and are strictly more accurate than re-parsing SQL text here
// -- see database_postgresql_adapter.go/database_mysql_adapter.go.
var (
	stringLiteralPattern  = regexp.MustCompile(`'(?:[^'\\]|\\.|'')*'`)
	numericLiteralPattern = regexp.MustCompile(`(?i)(?:\b|^)-?\d+(?:\.\d+)?\b`)
	whitespacePattern     = regexp.MustCompile(`\s+`)
)

// NormalizeQuery replaces string/numeric literals with `?` and collapses
// whitespace, so two queries that differ only in their parameter values
// normalize to the same string (spec #9's SELECT ... WHERE id = 100 vs.
// WHERE id = 200 example). Never stores or returns the original literal
// values.
func NormalizeQuery(sql string) string {
	s := stringLiteralPattern.ReplaceAllString(sql, "?")
	s = numericLiteralPattern.ReplaceAllString(s, "?")
	s = whitespacePattern.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

// Fingerprint returns a stable SHA-256 hex digest of an already-normalized
// identifier -- the normalized query text from NormalizeQuery, or an
// engine's own native identifier (a queryid/DIGEST rendered as a string).
// Never computed from raw, unnormalized query text.
func Fingerprint(normalized string) string {
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

// TruncateQueryText bounds any query text this application ever persists
// (spec #84) -- only ever called on already-normalized/parameterized text
// (never raw literals), and only when DATABASE_QUERY_TEXT_CAPTURE=true.
func TruncateQueryText(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	return s[:maxBytes]
}
