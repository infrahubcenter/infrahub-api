// Package httpx holds tiny HTTP response helpers shared by handlers and
// middleware. It exists separately from internal/handlers so middleware can
// use it without importing the handlers package (which would create an
// import cycle once handlers need context helpers from middleware).
package httpx

import (
	"encoding/json"
	"net/http"
)

// WriteJSON writes v as a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes a JSON error response of the form {"error": message}.
func WriteError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, map[string]string{"error": message})
}
