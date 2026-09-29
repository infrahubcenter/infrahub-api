// CORS preflight (OPTIONS) must advertise every HTTP method this app
// actually routes with -- PUT was missing here for a long time (silently
// breaking every PUT endpoint -- SSH credential config, container/pod
// rename, K8s monitoring toggle, alert rule update, notification policy
// update, "me settings" update, and the newer Dashboard monitoring/logs
// config -- for any cross-origin browser call, which is exactly this
// app's normal dev setup, frontend on :3000 calling the backend on :8080)
// until the Dashboard Monitoring/Logs Configure feature's own PUT calls
// surfaced it. This test locks in every method actually used by
// router.go so a similar gap can't reappear unnoticed.
package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCORS_PreflightAllowsEveryMethodTheRouterUses(t *testing.T) {
	handler := CORS("http://localhost:3000")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/dashboards/00000000-0000-0000-0000-000000000000/monitoring-config", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rec.Code)
	}
	allowed := rec.Header().Get("Access-Control-Allow-Methods")
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		if !strings.Contains(allowed, method) {
			t.Errorf("Access-Control-Allow-Methods %q is missing %s -- every PUT/PATCH/etc. route in router.go would be unreachable from a real browser", allowed, method)
		}
	}
}
