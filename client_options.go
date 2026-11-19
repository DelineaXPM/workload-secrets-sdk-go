package workloadsecrets

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// TokenSource supplies a bearer access token for outgoing API requests.
// Implementations may cache and refresh the token internally; NewClient
// calls Token once per outgoing request.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Behavior tunes the SDK's resilience. A zero value keeps the default.
type Behavior struct {
	// PerAttemptTimeout bounds one attempt, including reading the response headers. Default 15 s.
	PerAttemptTimeout time.Duration
	// TotalTimeout bounds the whole call: every attempt and every wait between attempts. Default 60 s.
	TotalTimeout time.Duration
}

// ClientOptions is per-environment configuration for the Workload Secrets Public API SDK.
type ClientOptions struct {
	BaseURL       string
	TenantID      string
	ClientID      string
	ClientSecret  string
	TokenEndpoint string

	// TokenSource, when set, bypasses the ClientID/ClientSecret/TokenEndpoint
	// OAuth2 client-credentials flow and supplies the bearer token directly —
	// the seam a caller with its own token-acquisition flow (e.g. the CLI's
	// device-code login) uses to feed NewClient a token it acquired itself.
	TokenSource TokenSource

	// Behavior overrides the default timeouts.
	Behavior Behavior

	// Transport is the base round tripper requests are finally sent through, for a proxy or custom TLS settings.
	// Default http.DefaultTransport.
	Transport http.RoundTripper

	// Logger receives a debug record for each retry. Nil logs nothing. Records carry the method, path, attempt,
	// wait, status and error text, never headers or bodies.
	Logger *slog.Logger
}

// hidden stands in for the client secret wherever ClientOptions is printed.
const hidden = "[hidden]"

func (o ClientOptions) secretShown() string {
	if o.ClientSecret == "" {
		return ""
	}
	return hidden
}

// String shows the options without the client secret, so printing or logging them never leaks it.
func (o ClientOptions) String() string {
	return fmt.Sprintf("ClientOptions{BaseURL: %q, TenantID: %q, ClientID: %q, ClientSecret: %q, TokenEndpoint: %q, TokenSource: %t, Behavior: %+v}",
		o.BaseURL, o.TenantID, o.ClientID, o.secretShown(), o.TokenEndpoint, o.TokenSource != nil, o.Behavior)
}

// GoString is String, so %#v hides the client secret too.
func (o ClientOptions) GoString() string { return o.String() }

// LogValue keeps the client secret out of log/slog records.
func (o ClientOptions) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("baseURL", o.BaseURL),
		slog.String("tenantID", o.TenantID),
		slog.String("clientID", o.ClientID),
		slog.String("clientSecret", o.secretShown()),
		slog.String("tokenEndpoint", o.TokenEndpoint),
		slog.Bool("tokenSource", o.TokenSource != nil),
	)
}
