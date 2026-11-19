package workloadsecrets

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedirectTransport_FollowsRedirectWithBody(t *testing.T) {
	var secondRequestBody string
	requestCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path == "/original" {
			w.Header().Set("Location", "/redirected")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		body, _ := io.ReadAll(r.Body)
		secondRequestBody = string(body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	transport := &redirectTransport{maxRedirects: 5, next: http.DefaultTransport}
	client := &http.Client{Transport: transport}

	req, err := http.NewRequest(http.MethodPost, server.URL+"/original", strings.NewReader(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want 200", resp.StatusCode)
	}
	if requestCount != 2 {
		t.Errorf("got %d requests, want 2 (original + redirect)", requestCount)
	}
	if secondRequestBody != `{"hello":"world"}` {
		t.Errorf("redirected request body = %q, want the original body replayed", secondRequestBody)
	}
}

func TestRedirectTransport_PassesThroughNonRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	transport := &redirectTransport{maxRedirects: 5, next: http.DefaultTransport}
	client := &http.Client{Transport: transport}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got status %d, want 404 (passed through unchanged)", resp.StatusCode)
	}
}

func TestIsRedirectStatus(t *testing.T) {
	cases := map[int]bool{
		http.StatusOK:                false,
		http.StatusNotFound:          false,
		http.StatusFound:             false, // 302 is deliberately not handled -- only 307/308 preserve body+method
		http.StatusTemporaryRedirect: true,
		http.StatusPermanentRedirect: true,
	}
	for status, want := range cases {
		if got := isRedirectStatus(status); got != want {
			t.Errorf("isRedirectStatus(%d) = %v, want %v", status, got, want)
		}
	}
}

func TestRedirectTransport_DoesNotFollowCrossOriginRedirect(t *testing.T) {
	otherRequests := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherRequests++
	}))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", other.URL+"/moved")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	client := &http.Client{
		Transport:     &redirectTransport{maxRedirects: 5, next: http.DefaultTransport},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, _ := http.NewRequest(http.MethodPost, origin.URL, strings.NewReader("body"))
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := client.Do(req)
	if resp != nil {
		resp.Body.Close()
	}

	var declined *RedirectNotFollowedError
	if !errors.As(err, &declined) || declined.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("err = %v, want a RedirectNotFollowedError for the 307", err)
	}
	if otherRequests != 0 {
		t.Errorf("the other origin received %d requests, want 0", otherRequests)
	}
}
