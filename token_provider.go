package workloadsecrets

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// tokenProvider supplies bearer tokens and discards one the API rejected.
type tokenProvider interface {
	Token(ctx context.Context) (string, error)
	Invalidate(rejected string)
}

// invalidator is implemented by a TokenSource that can discard a token the API rejected.
type invalidator interface {
	Invalidate(rejected string)
}

// externalTokenProvider adapts a caller's TokenSource. Invalidate is forwarded when the source supports it.
type externalTokenProvider struct {
	source TokenSource
}

func (p externalTokenProvider) Token(ctx context.Context) (string, error) {
	return p.source.Token(ctx)
}

func (p externalTokenProvider) Invalidate(rejected string) {
	if inv, ok := p.source.(invalidator); ok {
		inv.Invalidate(rejected)
	}
}

// clientCredentialsProvider caches one OAuth2 client-credentials token. The token request carries the credentials in the
// form body and runs with the context of the request that needs it. Concurrent callers share one fetch.
type clientCredentialsProvider struct {
	config *clientcredentials.Config
	mu     sync.Mutex
	cached *oauth2.Token
}

func newClientCredentialsProvider(options ClientOptions) *clientCredentialsProvider {
	return &clientCredentialsProvider{config: &clientcredentials.Config{
		ClientID:     options.ClientID,
		ClientSecret: options.ClientSecret,
		TokenURL:     options.TokenEndpoint,
		Scopes:       []string{tokenScope},
		AuthStyle:    oauth2.AuthStyleInParams,
	}}
}

func (p *clientCredentialsProvider) Token(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cached.Valid() {
		return p.cached.AccessToken, nil
	}
	token, err := p.fetch(ctx)
	if err != nil {
		return "", err
	}
	p.cached = token
	return token.AccessToken, nil
}

// fetch requests a token, trying at most twice. The token request is a POST, so only a failure that proves it was not
// processed is retried: a refused connection, 429, or 503 carrying Retry-After.
func (p *clientCredentialsProvider) fetch(ctx context.Context) (*oauth2.Token, error) {
	// The request carries the client secret, so it never goes over plain http (NewHTTPClient callers included).
	if err := requireHTTPS(p.config.TokenURL, "TokenEndpoint"); err != nil {
		return nil, err
	}
	policy := defaultRetryPolicy()
	policy.maxAttempts = 2
	for attempt := 1; ; attempt++ {
		token, err := p.config.Token(ctx)
		if err == nil {
			return token, nil
		}

		// A token endpoint answer is judged as a response; any other failure as a transport error.
		var resp *http.Response
		outcomeErr := err
		var retrieveErr *oauth2.RetrieveError
		if errors.As(err, &retrieveErr) && retrieveErr.Response != nil {
			resp, outcomeErr = retrieveErr.Response, nil
		}
		if attempt >= policy.maxAttempts || !policy.shouldRetry(ctx, false, resp, outcomeErr) {
			return nil, err
		}
		wait, ok := policy.delay(attempt, resp, rand.Float64)
		if !ok {
			return nil, err
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (p *clientCredentialsProvider) Invalidate(rejected string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cached != nil && p.cached.AccessToken == rejected {
		p.cached = nil
	}
}
