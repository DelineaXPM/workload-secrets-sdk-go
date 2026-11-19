package workloadsecrets

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

// authTransport attaches a bearer token to every request. A 401 discards the rejected token, fetches a new
// one and replays the request once. When no new token is available the 401 is returned as it is.
type authTransport struct {
	provider tokenProvider
	next     http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// NewClient refuses a plain http address up front; this also covers NewHTTPClient, whose caller picks each URL.
	if !secureOrLoopback(req.URL) {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, fmt.Errorf("workload secrets: refusing to send a token to %s://%s: it must use https", req.URL.Scheme, req.URL.Host)
	}
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body.Close()
	}

	token, err := t.provider.Token(req.Context())
	if err != nil {
		return nil, fmt.Errorf("resolve bearer token: %w", err)
	}
	resp, err := t.send(req, body, token)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}

	t.provider.Invalidate(token)
	renewed, err := t.provider.Token(req.Context())
	if err != nil || renewed == token {
		return resp, nil
	}
	resp.Body.Close()
	return t.send(req, body, renewed)
}

func (t *authTransport) send(req *http.Request, body []byte, token string) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		out.Body = io.NopCloser(bytes.NewReader(body))
		out.ContentLength = int64(len(body))
		out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	return t.next.RoundTrip(out)
}
