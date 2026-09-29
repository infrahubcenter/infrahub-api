package services

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// redisSlaveLinePattern matches one INFO replication `slaveN:` value,
// e.g. "ip=10.0.0.5,port=6379,state=online,offset=12345,lag=0" -- Redis
// reports lag directly, no derivation needed.
var redisSlaveLinePattern = regexp.MustCompile(`lag=(\d+)`)

// ParseRedisInfo parses a Redis/Valkey `INFO` reply (key:value lines
// grouped under "# Section" headers, blank lines between sections) into a
// flat map -- every downstream metric is read from this map, never a raw
// command re-run.
func ParseRedisInfo(output string) map[string]string {
	result := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		result[line[:idx]] = line[idx+1:]
	}
	return result
}

// ParseRedisMetrics turns ParseRedisInfo's map into a MetricsResult: hit
// rate is only calculated when at least one of hits/misses is nonzero,
// and memory percentage is only shown (by the caller) when maxmemory is
// actually set to a nonzero limit -- never a fake percentage when
// unlimited.
func ParseRedisMetrics(info map[string]string) MetricsResult {
	m := MetricsResult{Details: map[string]any{}, RawCounters: map[string]float64{}}

	if v, ok := redisInt(info, "connected_clients"); ok {
		m.Common.Connections = &v
	}
	if v, ok := redisInt(info, "used_memory"); ok {
		m.Common.MemoryUsageBytes = &v
	}
	if v, ok := redisInt(info, "uptime_in_seconds"); ok {
		m.Common.UptimeSeconds = &v
	}
	if v, ok := redisFloat(info, "total_commands_processed"); ok {
		m.RawCounters["total_commands_processed"] = v
	} else {
		m.Partial = true
	}

	if blocked, ok := redisInt(info, "blocked_clients"); ok {
		m.Details["blocked_clients"] = blocked
	}
	if maxMem, ok := redisInt(info, "maxmemory"); ok && maxMem > 0 {
		m.Details["max_memory_bytes"] = maxMem
	}

	hits, hitsOK := redisFloat(info, "keyspace_hits")
	misses, missesOK := redisFloat(info, "keyspace_misses")
	if hitsOK && missesOK && (hits+misses) > 0 {
		m.Details["hit_rate"] = roundTo(hits/(hits+misses)*100, 1)
	}

	if role, ok := info["role"]; ok {
		m.Details["role"] = role
	}
	if slaves, ok := redisInt(info, "connected_slaves"); ok {
		m.Details["connected_replicas"] = slaves
	}

	keyCount := int64(0)
	for k, v := range info {
		if !strings.HasPrefix(k, "db") {
			continue
		}
		if n, ok := parseRedisKeyCount(v); ok {
			keyCount += n
		}
	}
	m.Details["key_count"] = keyCount

	if m.Partial {
		m.Warning = "one or more optional Redis statistics were unavailable"
	}
	return m
}

// parseRedisKeyCount parses one `dbN` INFO line's value, e.g.
// "keys=42,expires=3,avg_ttl=0".
func parseRedisKeyCount(v string) (int64, bool) {
	for _, part := range strings.Split(v, ",") {
		if strings.HasPrefix(part, "keys=") {
			n, err := strconv.ParseInt(strings.TrimPrefix(part, "keys="), 10, 64)
			if err != nil {
				return 0, false
			}
			return n, true
		}
	}
	return 0, false
}

func redisInt(info map[string]string, key string) (int64, bool) {
	v, ok := info[key]
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func redisFloat(info map[string]string, key string) (float64, bool) {
	v, ok := info[key]
	if !ok {
		return 0, false
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

func roundTo(v float64, places int) float64 {
	mult := 1.0
	for i := 0; i < places; i++ {
		mult *= 10
	}
	return float64(int64(v*mult+0.5)) / mult
}

// mongoURIEscape percent-encodes characters that would otherwise be
// interpreted as URI delimiters inside a username/password component.
func mongoURIEscape(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch r {
		case ':', '/', '@', '%', '?', '#', '[', ']':
			fmt.Fprintf(&b, "%%%02X", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
