package handler

import "net/http"

// APIError represents a standardized API error response.
type APIError struct {
	Code       string
	Message    string
	HTTPStatus int
}

// Predefined API errors.
var (
	ErrRateLimited      = &APIError{Code: "rate_limited",      Message: "Too many requests",               HTTPStatus: http.StatusTooManyRequests}
	ErrNoIP             = &APIError{Code: "no_ip",             Message: "Could not determine client IP",   HTTPStatus: http.StatusForbidden}
	ErrMethodNotAllowed = &APIError{Code: "method_not_allowed", Message: "Method not allowed",             HTTPStatus: http.StatusMethodNotAllowed}
	ErrInvalidForm      = &APIError{Code: "invalid_form",      Message: "Invalid form data",               HTTPStatus: http.StatusBadRequest}
	ErrInvalidKey       = &APIError{Code: "invalid_key",       Message: "Invalid key",                     HTTPStatus: http.StatusUnauthorized}
	ErrMissingKey       = &APIError{Code: "missing_key",       Message: "Missing key parameter",           HTTPStatus: http.StatusBadRequest}
	ErrNotConfigured    = &APIError{Code: "not_configured",    Message: "Key authorization not configured", HTTPStatus: http.StatusOK}
	ErrApprovalFailed   = &APIError{Code: "approval_failed",   Message: "Approval failed",                 HTTPStatus: http.StatusInternalServerError}
	ErrRevokeFailed     = &APIError{Code: "revoke_failed",     Message: "Revoke failed",                   HTTPStatus: http.StatusBadRequest}
)

// writeAPIError sends a standardized JSON error response.
func writeAPIError(w http.ResponseWriter, err *APIError, extra map[string]interface{}) {
	resp := map[string]interface{}{
		"error":   err.Code,
		"message": err.Message,
	}
	for k, v := range extra {
		resp[k] = v
	}
	writeJSON(w, err.HTTPStatus, resp)
}
