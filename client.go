package workloadsecrets

import (
	"net/http"
	"strings"

	"github.com/microsoft/kiota-abstractions-go/authentication"
	"github.com/microsoft/kiota-abstractions-go/serialization"
	kiotahttp "github.com/microsoft/kiota-http-go"

	generated "github.com/DelineaXPM/workload-secrets-sdk-go/generated"
)

// tokenScope is Identity's fixed integration scope for the Workload Secrets Public API -- not per-environment.
const tokenScope = "xpmheadless"

// NewHTTPClient builds the same authenticated (retry + tenant header +
// bearer/OAuth2) *http.Client NewClient wires internally, for callers that
// need to issue requests the generated SDK can't express (e.g. a
// multipart/form-data body) against the same tenant/credentials. It carries
// no base URL — callers resolve request URLs themselves.
func NewHTTPClient(options ClientOptions) *http.Client {
	policy := defaultRetryPolicy()
	if options.Behavior.PerAttemptTimeout > 0 {
		policy.perAttempt = options.Behavior.PerAttemptTimeout
	}
	if options.Behavior.TotalTimeout > 0 {
		policy.total = options.Behavior.TotalTimeout
	}

	var provider tokenProvider
	if options.TokenSource != nil {
		provider = externalTokenProvider{source: options.TokenSource}
	} else {
		provider = newClientCredentialsProvider(options)
	}

	base := options.Transport
	if base == nil {
		base = http.DefaultTransport
	}

	// Outermost first: tenant header, user agent, retry (with the timeouts), bearer token with 401 replay, redirect, network.
	transport := newRetryTransport(policy, newOperationSafety(options.BaseURL), &authTransport{
		provider: provider,
		next: &redirectTransport{
			maxRedirects: 5,
			next:         base,
		},
	}, options.Logger)
	return &http.Client{
		Transport: &tenantHeaderTransport{
			tenantID: options.TenantID,
			next:     &userAgentTransport{value: userAgent(), next: transport},
		},
		// redirectTransport owns redirect handling; the client must not follow a redirect it declined.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// NewClient builds a WorkloadSecretsApiClient wired with retry and the tenant header,
// authenticated either via OAuth2 client-credentials (the default) or via
// options.TokenSource when set.
func NewClient(options ClientOptions) (*generated.WorkloadSecretsApiClient, error) {
	if err := requireHTTPS(options.BaseURL, "BaseURL"); err != nil {
		return nil, err
	}
	if options.TokenSource == nil && options.TokenEndpoint != "" {
		if err := requireHTTPS(options.TokenEndpoint, "TokenEndpoint"); err != nil {
			return nil, err
		}
	}
	httpClient := NewHTTPClient(options)

	// Token acquisition and injection happen in the httpClient's transport chain above, not via a kiota
	// AuthenticationProvider -- the anonymous provider is a documented no-op for that abstraction.
	adapter, err := kiotahttp.NewNetHttpRequestAdapterWithParseNodeFactoryAndSerializationWriterFactoryAndHttpClient(
		&authentication.AnonymousAuthenticationProvider{},
		serialization.DefaultParseNodeFactoryInstance,
		serialization.DefaultSerializationWriterFactoryInstance,
		httpClient,
	)
	if err != nil {
		return nil, err
	}
	// The generated request paths start with "/", so a trailing slash on the base URL would double it.
	adapter.SetBaseUrl(strings.TrimRight(options.BaseURL, "/"))

	return generated.NewWorkloadSecretsApiClient(adapter), nil
}
