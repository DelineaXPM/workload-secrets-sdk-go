package workloadsecrets

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	generated "github.com/DelineaXPM/workload-secrets-sdk-go/generated"
)

func TestRetrySafetyTable_MarksTheMintUnsafeAndTheSecretReadSafe(t *testing.T) {
	want := map[string]bool{
		http.MethodGet + " /api/v1/secrets/data/{path}":  true,
		http.MethodPost + " /api/v1/secrets/mint/{path}": false,
	}
	found := map[string]bool{}
	for _, operation := range generated.RetrySafetyTable() {
		key := operation.Method + " " + operation.PathTemplate
		if safe, ok := want[key]; ok {
			found[key] = true
			if operation.RetrySafe != safe {
				t.Errorf("%s retry-safe = %v, want %v: minting creates a credential, reading changes nothing", key, operation.RetrySafe, safe)
			}
		}
	}
	for key := range want {
		if !found[key] {
			t.Errorf("%s is missing from the table", key)
		}
	}
}

func TestTemplatePattern_TrailingParameterSpansSegmentsAndInnerParameterDoesNot(t *testing.T) {
	trailing := templatePattern("/api/v1/secrets/data/{path}")
	for path, want := range map[string]bool{
		"/api/v1/secrets/data/one":             true,
		"/api/v1/secrets/data/ci/payments/api": true,
		"/api/v1/secrets/data/":                false,
		"/api/v1/secrets/metadata/one":         false,
	} {
		if got := trailing.MatchString(path); got != want {
			t.Errorf("trailing template on %q = %v, want %v", path, got, want)
		}
	}

	inner := templatePattern("/api/v1/pki/ca/{name}/crl")
	for path, want := range map[string]bool{
		"/api/v1/pki/ca/root/crl":      true,
		"/api/v1/pki/ca/a%2Fb/crl":     true,
		"/api/v1/pki/ca/a/b/crl":       false,
		"/api/v1/pki/ca/root/crl/more": false,
	} {
		if got := inner.MatchString(path); got != want {
			t.Errorf("inner template on %q = %v, want %v", path, got, want)
		}
	}
}

func TestOperationSafety_FollowsTheContractFlagNotTheMethod(t *testing.T) {
	safety := newOperationSafety("https://tenant.example/workload-secrets/")
	cases := []struct {
		method string
		target string
		want   bool
	}{
		{http.MethodPost, "https://tenant.example/workload-secrets/api/v1/secrets/mint/ci%2Fpayments%2Fapi", false},
		{http.MethodPost, "https://tenant.example/workload-secrets/api/v1/secrets/mint/ci/payments/api", false},
		{http.MethodGet, "https://tenant.example/workload-secrets/api/v1/secrets/data/ci/payments/api", true},
		{http.MethodGet, "https://tenant.example/workload-secrets/api/v1/secrets/metadata/ci%2Fpayments", true},
		{http.MethodGet, "https://tenant.example/workload-secrets/api/v1/policies", true},
		{http.MethodPost, "https://tenant.example/workload-secrets/api/v1/policies", false},
		{http.MethodGet, "https://tenant.example/workload-secrets/not/in/the/contract", true},
		{http.MethodDelete, "https://tenant.example/workload-secrets/not/in/the/contract", false},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.target, nil)
		if got := safety.retrySafe(req); got != c.want {
			t.Errorf("%s %s = %v, want %v", c.method, c.target, got, c.want)
		}
	}
}

func TestRetryTransport_DoesNotResendTheMintAfter502ButRetriesTheSecretRead(t *testing.T) {
	var mintCalls, readCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/workload-secrets/api/v1/secrets/mint/db/dynamic":
			mintCalls.Add(1)
			w.WriteHeader(http.StatusBadGateway)
		case "/workload-secrets/api/v1/secrets/data/db/static":
			if readCalls.Add(1) < 2 {
				w.WriteHeader(http.StatusBadGateway)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	base := server.URL + "/workload-secrets"
	client := &http.Client{Transport: newRetryTransport(fastPolicy(), newOperationSafety(base), http.DefaultTransport, nil)}

	resp, err := client.Post(base+"/api/v1/secrets/mint/db%2Fdynamic", "application/json", nil)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	resp.Body.Close()
	if mintCalls.Load() != 1 {
		t.Errorf("mint sent %d times, want 1: a resend could create another credential", mintCalls.Load())
	}

	resp, err = client.Get(base + "/api/v1/secrets/data/db%2Fstatic")
	if err != nil {
		t.Fatalf("secret read: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || readCalls.Load() != 2 {
		t.Errorf("secret read: status %d after %d calls, want 200 after 2", resp.StatusCode, readCalls.Load())
	}
}
