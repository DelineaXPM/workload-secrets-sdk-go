package workloadsecrets

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func newTokenServer(t *testing.T, requests *atomic.Int32, lastBody *atomic.Value, lastAuth *atomic.Value) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		_ = r.ParseForm()
		lastBody.Store(r.Form.Encode())
		lastAuth.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + string(rune('0'+n)) + `","token_type":"Bearer","expires_in":3600}`))
	}))
}

func TestClientCredentialsProvider_CachesAndSendsCredentialsInBody(t *testing.T) {
	var requests atomic.Int32
	var body, auth atomic.Value
	server := newTokenServer(t, &requests, &body, &auth)
	defer server.Close()

	provider := newClientCredentialsProvider(ClientOptions{ClientID: "cid", ClientSecret: "secret", TokenEndpoint: server.URL})
	first, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	second, _ := provider.Token(context.Background())

	if first != second || requests.Load() != 1 {
		t.Errorf("tokens %q and %q after %d requests, want one cached token from one request", first, second, requests.Load())
	}
	if got, _ := body.Load().(string); !strings.Contains(got, "client_secret=secret") || !strings.Contains(got, "scope=xpmheadless") {
		t.Errorf("token request form = %q, want the credentials and scope in the body", got)
	}
	if got, _ := auth.Load().(string); got != "" {
		t.Errorf("token request Authorization = %q, want none", got)
	}
}

func TestClientCredentialsProvider_InvalidateForcesNewToken(t *testing.T) {
	var requests atomic.Int32
	var body, auth atomic.Value
	server := newTokenServer(t, &requests, &body, &auth)
	defer server.Close()

	provider := newClientCredentialsProvider(ClientOptions{ClientID: "cid", ClientSecret: "secret", TokenEndpoint: server.URL})
	first, _ := provider.Token(context.Background())
	provider.Invalidate("some-other-token")
	if again, _ := provider.Token(context.Background()); again != first {
		t.Errorf("invalidating a different token changed the cached token")
	}
	provider.Invalidate(first)
	renewed, _ := provider.Token(context.Background())

	if renewed == first || requests.Load() != 2 {
		t.Errorf("renewed %q (first %q) after %d requests, want a new token from a second request", renewed, first, requests.Load())
	}
}

func TestClientCredentialsProvider_RetriesTokenRequestOn503WithRetryAfter(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()

	provider := newClientCredentialsProvider(ClientOptions{ClientID: "cid", ClientSecret: "secret", TokenEndpoint: server.URL})
	token, err := provider.Token(context.Background())

	if err != nil || token != "tok" || requests.Load() != 2 {
		t.Errorf("token %q, err %v after %d requests, want tok after 2", token, err, requests.Load())
	}
}

func TestClientCredentialsProvider_DoesNotRetryTokenRequestOn500(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	provider := newClientCredentialsProvider(ClientOptions{ClientID: "cid", ClientSecret: "secret", TokenEndpoint: server.URL})
	if _, err := provider.Token(context.Background()); err == nil {
		t.Fatal("want an error from a 500 token response")
	}
	if requests.Load() != 1 {
		t.Errorf("requests = %d, want 1 (a POST is not retried on 500)", requests.Load())
	}
}
