package handlers

import (
	"errors"
	"net/http"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/services"
)

// deleteConfirmationRequest is the request body shape for every Delete
// endpoint that requires the caller to type the resource's exact current
// name before the backend will act (Workspace/VM/Database/Object
// Storage).
type deleteConfirmationRequest struct {
	ConfirmationName string `json:"confirmation_name"`
}

// writeServiceError maps a services-package sentinel error to the
// appropriate HTTP status and a safe message, so every management handler
// (workspaces/resources/vms/access) responds consistently instead of each
// reimplementing this switch.
func writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, services.ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not found")
	case errors.Is(err, services.ErrDuplicateName):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, services.ErrValidation):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, services.ErrLastActiveAdmin):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, services.ErrLastActiveOwner):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, services.ErrSelfDemotionConfirmationRequired):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, services.ErrCannotDeleteSelf):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, services.ErrConfirmationMismatch):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, services.ErrHasDependencies):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, services.ErrInvalidSSHKey):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, services.ErrPassphraseProtectedKey):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	default:
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
	}
}
