package httpx

import "strings"

// OriginAllowed reports whether origin is one of allowed, a comma-separated
// list of origins (FRONTEND_ORIGIN). One deployment can then be used from
// several consoles at once -- e.g. the hosted console plus a local one --
// while every WebSocket upgrade and CORS response still only ever admits
// an explicitly listed origin.
func OriginAllowed(allowed, origin string) bool {
	if origin == "" {
		return false
	}
	for _, a := range strings.Split(allowed, ",") {
		if strings.TrimRight(strings.TrimSpace(a), "/") == origin {
			return true
		}
	}
	return false
}

// FirstOrigin returns the first entry of a comma-separated origin list.
func FirstOrigin(allowed string) string {
	first, _, _ := strings.Cut(allowed, ",")
	return strings.TrimRight(strings.TrimSpace(first), "/")
}
