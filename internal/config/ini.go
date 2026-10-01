package config

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

type keyValue struct {
	key   string
	value string
}

// parseINI reads KEY=VALUE text: the INI format of config files and the
// .env format alike. Deliberately hand-rolled -- the format is tiny:
//   - "#" and ";" start a full-line comment; blank lines are skipped;
//   - [section] headers are only for human organization and are ignored
//     (every key becomes a plain environment variable);
//   - an "export " prefix (shell-style .env files) is allowed;
//   - a value may be wrapped in double or single quotes to keep leading/
//     trailing spaces or a literal "#"/";".
//
// name is only used in error messages.
func parseINI(content []byte, name string) ([]keyValue, error) {
	var out []keyValue
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if lineNum == 1 {
			line = strings.TrimPrefix(line, "\uFEFF") // UTF-8 BOM from Windows editors
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			return nil, fmt.Errorf("%s:%d: expected KEY=VALUE", name, lineNum)
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		if len(value) >= 2 && (value[0] == '"' && value[len(value)-1] == '"' || value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}
		if key == "" {
			return nil, fmt.Errorf("%s:%d: empty key", name, lineNum)
		}
		out = append(out, keyValue{key: key, value: value})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return out, nil
}
