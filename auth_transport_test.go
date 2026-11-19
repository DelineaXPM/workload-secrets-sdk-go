package workloadsecrets

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeProvider hands out the queued tokens in order, repeating the last, and records invalidations.
type fakeProvider struct {
	mu          sync.Mutex
	tokens      []string
	calls       int
	invalidated []string
}

func (p *fakeProvider) Token(context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	i := p.calls
	if i >= len(p.tokens) {
		i = len(p.tokens) - 1
	}
	p.calls++
	return p.tokens[i], nil
}

func (p *fakeProvider) Invalidate(rejected string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.invalidated = append(p.invalidated, rejected)
}

func TestAuthTransport_AttachesBearer(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
	}))
	defer server.Close()

	client := &http.Client{Transport: &authTransport{provider: &fakeProvider{tokens: []string{"t1"}}, next: http.DefaultTransport}}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()

	if got != "Bearer t1" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer t1")
	}
}

func TestAuthTransport_ReplaysOnceAfter401WithNewTokenAndBody(t *testing.T) {
	var seen []string
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, r.Header.Get("Authorization"))
		bodies = append(bodies, string(b))
		if r.Header.Get("Authorization") == "Bearer t1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	provider := &fakeProvider{tokens: []string{"t1", "t2"}}
	client := &http.Client{Transport: &authTransport{provider: provider, next: http.DefaultTransport}}
	resp, err := client.Post(server.URL, "application/json", strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201 from the replay", resp.StatusCode)
	}
	if len(seen) != 2 || seen[0] != "Bearer t1" || seen[1] != "Bearer t2" {
		t.Errorf("Authorization headers = %v, want [Bearer t1 Bearer t2]", seen)
	}
	if len(bodies) != 2 || bodies[0] != `{"a":1}` || bodies[1] != `{"a":1}` {
		t.Errorf("bodies = %v, want the body on both attempts", bodies)
	}
	if len(provider.invalidated) != 1 || provider.invalidated[0] != "t1" {
		t.Errorf("invalidated = %v, want [t1]", provider.invalidated)
	}
}

func TestAuthTransport_DoesNotReplayWhenTokenIsUnchanged(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := &http.Client{Transport: &authTransport{provider: &fakeProvider{tokens: []string{"same"}}, next: http.DefaultTransport}}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want the original 401", resp.StatusCode)
	}
	if requests != 1 {
		t.Errorf("requests = %d, want 1 (no replay with the same token)", requests)
	}
}

func TestAuthTransport_SendsKnownContentLength(t *testing.T) {
	var length int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		length = r.ContentLength
	}))
	defer server.Close()

	req, _ := http.NewRequest(http.MethodPost, server.URL, io.NopCloser(strings.NewReader("12345")))
	client := &http.Client{Transport: &authTransport{provider: &fakeProvider{tokens: []string{"t"}}, next: http.DefaultTransport}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if length != 5 {
		t.Errorf("server saw ContentLength %d, want 5 (not chunked)", length)
	}
}
