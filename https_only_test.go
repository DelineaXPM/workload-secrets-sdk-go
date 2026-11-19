package workloadsecrets

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type staticTokenSource string

func (s staticTokenSource) Token(context.Context) (string, error) { return string(s), nil }

// toServer sends every request to srv whatever host the URL names, so a test can use a non-loopback http address
// without the network.
type toServer struct{ srv *httptest.Server }

func (t toServer) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.URL.Host = strings.TrimPrefix(t.srv.URL, "http://")
	return http.DefaultTransport.RoundTrip(out)
}

func TestNewClient_RefusesPlainHTTPExceptLoopback(t *testing.T) {
	for _, tc := range []struct {
		baseURL string
		allowed bool
	}{
		{"https://example.delinea.app/workload-secrets", true},
		{"http://localhost:8080", true},
		{"http://127.0.0.1:8080", true},
		{"http://[::1]:8080", true},
		{"http://example.delinea.app/workload-secrets", false},
		{"HTTP://EXAMPLE.DELINEA.APP", false},
		{"ftp://example.delinea.app", false},
		{"example.delinea.app", false},
		{"", false},
	} {
		_, err := NewClient(ClientOptions{BaseURL: tc.baseURL, TokenSource: staticTokenSource("t")})
		if (err == nil) != tc.allowed {
			t.Errorf("BaseURL %q: err = %v, want allowed = %t", tc.baseURL, err, tc.allowed)
		}
	}
}

func TestNewClient_RefusesAPlainHTTPTokenEndpoint(t *testing.T) {
	_, err := New(ClientOptions{
		BaseURL:       "https://example.delinea.app/workload-secrets",
		TokenEndpoint: "http://example.delinea.app/identity/oauth2/token/xpmplatform",
		ClientID:      "id",
		ClientSecret:  "SENTINEL-SECRET",
	})
	if err == nil || !strings.Contains(err.Error(), "TokenEndpoint must use https") {
		t.Fatalf("err = %v, want a TokenEndpoint https error", err)
	}
}

func TestNewHTTPClient_NeverSendsTheTokenOverPlainHTTP(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	defer srv.Close()

	client := NewHTTPClient(ClientOptions{TokenSource: staticTokenSource("SENTINEL-TOKEN"), Transport: toServer{srv}})
	resp, err := client.Get("http://example.delinea.app/workload-secrets/api/v1/secrets/data/a")
	if err == nil {
		resp.Body.Close()
		t.Fatal("want an error, the request went out")
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("server received %d request(s), want 0", n)
	}
}

func TestNewHTTPClient_NeverSendsTheClientSecretOverPlainHTTP(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	defer srv.Close()

	client := NewHTTPClient(ClientOptions{
		TokenEndpoint: "http://example.delinea.app/identity/oauth2/token/xpmplatform",
		ClientID:      "id",
		ClientSecret:  "SENTINEL-SECRET",
	})
	// The API URL is loopback, so only the token endpoint's address can stop the call.
	resp, err := client.Get(srv.URL + "/api/v1/secrets/data/a")
	if err == nil {
		resp.Body.Close()
		t.Fatal("want an error, the call went through")
	}
	if !strings.Contains(err.Error(), "TokenEndpoint must use https") {
		t.Fatalf("err = %v, want a TokenEndpoint https error", err)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("API received %d request(s), want 0", n)
	}
}

func TestClientOptions_PrintingNeverShowsTheClientSecret(t *testing.T) {
	options := ClientOptions{BaseURL: "https://example.delinea.app", ClientID: "my-client", ClientSecret: "SENTINEL-SECRET"}

	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("options", "options", options)

	for name, out := range map[string]string{
		"%v":   fmt.Sprintf("%v", options),
		"%+v":  fmt.Sprintf("%+v", options),
		"%#v":  fmt.Sprintf("%#v", options),
		"%s":   fmt.Sprintf("%s", options),
		"&%v":  fmt.Sprintf("%v", &options),
		"slog": logged.String(),
	} {
		if strings.Contains(out, "SENTINEL-SECRET") {
			t.Errorf("%s shows the client secret: %s", name, out)
		}
		if !strings.Contains(out, "my-client") {
			t.Errorf("%s lost the client ID: %s", name, out)
		}
	}
}
