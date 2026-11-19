package workloadsecrets

import (
	"errors"
	"fmt"
	"net/http"

	abstractions "github.com/microsoft/kiota-abstractions-go"
)

// Sentinel errors for the failures a caller usually handles. Test with errors.Is; an *APIError matches the one for its
// status code.
var (
	// ErrUnauthorized: the API rejected the token (401). Check the credentials, tenant and token endpoint.
	ErrUnauthorized = errors.New("workload secrets: unauthorized")
	// ErrForbidden: an authorization policy denies the call (403).
	ErrForbidden = errors.New("workload secrets: forbidden")
	// ErrNotFound: nothing exists at the path, or that version (404).
	ErrNotFound = errors.New("workload secrets: not found")
	// ErrConflict: the request conflicts with the current state (409), for example an engine that must be upgraded.
	ErrConflict = errors.New("workload secrets: conflict")
)

// APIError is an error response from the Workload Secrets API. Its message carries the status, the API's errorCode and
// title, never a response body or a secret value. Unwrap returns the generated client's error.
type APIError struct {
	StatusCode int
	// ErrorCode is the API's machine-readable code (for example "secret_not_found"); empty when the response had no
	// Problem Details body.
	ErrorCode string
	Title     string
	err       error
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("%d %s", e.StatusCode, http.StatusText(e.StatusCode))
	if e.ErrorCode != "" {
		msg += " [" + e.ErrorCode + "]"
	}
	if e.Title != "" && e.Title != e.ErrorCode {
		msg += ": " + e.Title
	}
	return msg
}

// Is reports whether target is the sentinel error for e's status code.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrUnauthorized:
		return e.StatusCode == http.StatusUnauthorized
	case ErrForbidden:
		return e.StatusCode == http.StatusForbidden
	case ErrNotFound:
		return e.StatusCode == http.StatusNotFound
	case ErrConflict:
		return e.StatusCode == http.StatusConflict
	default:
		return false
	}
}

func (e *APIError) Unwrap() error { return e.err }

// problemDetails is satisfied by the generated ApiProblemDetails and ApiValidationProblemDetails.
type problemDetails interface {
	error
	GetStatusCode() int
	GetErrorCode() *string
	GetTitle() *string
}

// asAPIError turns an error from the generated client into an *APIError when it is an API response, and returns any
// other error (transport, timeout, cancellation) unchanged. Kiota returns Problem Details for the statuses an operation
// declares with a body, and a bare *abstractions.ApiError for the rest (401, 403, and sometimes 404).
func asAPIError(err error) error {
	var problem problemDetails
	if errors.As(err, &problem) {
		return &APIError{StatusCode: problem.GetStatusCode(), ErrorCode: deref(problem.GetErrorCode()), Title: deref(problem.GetTitle()), err: err}
	}
	var apiErr *abstractions.ApiError
	if errors.As(err, &apiErr) {
		return &APIError{StatusCode: apiErr.GetStatusCode(), err: err}
	}
	return err
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
