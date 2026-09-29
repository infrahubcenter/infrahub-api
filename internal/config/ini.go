package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// parseINIFile reads a minimal INI-style file into a flat key/value map.
// Deliberately hand-rolled rather than a third-party INI library: the
// format this app actually needs is tiny (KEY = VALUE lines, optional
// [section] headers purely for human organization -- section names are
// discarded, since every key becomes a plain environment variable
// regardless of which section it was written under), and keeping the
// parser this small means anyone can read exactly what it does. "#" and
// ";" start a full-line comment; blank lines are skipped; a value may be
// wrapped in double quotes to preserve leading/trailing whitespace or
// embed a literal "#"/";" that would otherwise start a comment.
//
// Returns (nil, nil) if the file doesn't exist -- callers treat "no such
// file" as "nothing to load" (mirrors godotenv.Load's own best-effort
// convention this replaces), never an error.
func parseINIFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			continue // section header -- organizational only, not part of the key
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			return nil, fmt.Errorf("%s:%d: expected KEY=VALUE, got %q", path, lineNum, line)
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		if key == "" {
			return nil, fmt.Errorf("%s:%d: empty key", path, lineNum)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return values, nil
}
