package workloadsecrets

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient_AcceptsABaseURLWithATrailingSlash(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/token" {
			_, _ = w.Write([]byte(`{"access_token":"t","token_type":"Bearer","expires_in":3600}`))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		BaseURL:       server.URL + "/workload-secrets/",
		TenantID:      "t1",
		ClientID:      "c",
		ClientSecret:  "s",
		TokenEndpoint: server.URL + "/token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Api().V1().Policies().Get(context.Background(), nil); err != nil {
		t.Fatalf("Get: %v", err)
	}

	want := "/workload-secrets/api/v1/policies"
	if paths[len(paths)-1] != want {
		t.Errorf("request path = %q, want %q", paths[len(paths)-1], want)
	}
}
