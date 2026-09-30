package handlers

import (
	"net/http"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/services"
)

// License reports this installation's plan, its limits and current usage
// -- the source for the console's Plans & Billing page. Any signed-in user.
func License(licenses *services.LicenseService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if licenses == nil {
			httpx.WriteError(w, http.StatusNotFound, "not available")
			return
		}
		usage, err := licenses.Usage(r.Context())
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not read usage")
			return
		}
		out := map[services.LimitKind]int{}
		for _, k := range services.AllLimitKinds {
			out[k] = usage[k]
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"license": licenses.License(),
			"usage":   out,
		})
	}
}
