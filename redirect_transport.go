package workloadsecrets

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// redirectTransport manually follows 307/308 redirects to the same origin, replaying the request body on each hop.
//
// Go's own http.Client redirect handling refuses to auto-follow a 307/308 for a request with a
// body unless Request.GetBody is set -- kiota-http-go's request construction doesn't set it. The
// tenant's WAF (Imperva) 307-redirects any request whose path segment is percent-encoded (%2F is
// normalized to a literal "/"), which every generated builder's {*path} URL template produces.
// Without this transport, that redirect silently becomes the final response for any
// POST/PUT/DELETE-with-body call: no error, empty body, and Kiota treats a bodyless success as a
// nil result rather than an error -- e.g. Secrets().Data().ByPath(path).Post(...) would return
// (nil, nil) instead of ever reaching the real endpoint. GET is unaffected: no body means nothing
// blocks Go's default redirect-following.
type redirectTransport struct {
	maxRedirects int
	next         http.RoundTripper
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body.Close()
	}

	for redirects := 0; ; redirects++ {
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}

		resp, err := t.next.RoundTrip(req)
		if err != nil || !isRedirectStatus(resp.StatusCode) || redirects >= t.maxRedirects {
			return resp, err
		}

		location := resp.Header.Get("Location")
		if location == "" {
			return resp, nil
		}
		target, parseErr := req.URL.Parse(location)
		if parseErr != nil {
			return resp, nil
		}
		if !sameOrigin(req.URL, target) {
			resp.Body.Close()
			return nil, &RedirectNotFollowedError{StatusCode: resp.StatusCode, Location: target.String()}
		}
		resp.Body.Close()

		req = req.Clone(req.Context())
		req.URL = target
		req.Host = ""
	}
}

// sameOrigin reports whether both URLs share scheme, host and port. A redirect to another origin is not followed, so no
// request and no credentials reach it.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// RedirectNotFollowedError is returned when the API answers with a redirect to a different origin. The request is not
// sent there, so neither the request nor its credentials leave the configured origin. Without an error, the generated
// client would treat the bodyless 3xx as a successful empty result.
type RedirectNotFollowedError struct {
	StatusCode int
	Location   string
}

func (e *RedirectNotFollowedError) Error() string {
	return fmt.Sprintf("redirect (%d) to another origin not followed: %s", e.StatusCode, e.Location)
}

func isRedirectStatus(statusCode int) bool {
	return statusCode == http.StatusTemporaryRedirect || statusCode == http.StatusPermanentRedirect
}
