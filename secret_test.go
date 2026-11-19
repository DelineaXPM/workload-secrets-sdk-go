package workloadsecrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

// secretServer answers the secret read for one path with status and body, and records the last request.
type secretServer struct {
	*httptest.Server
	calls     atomic.Int32
	lastQuery string
}

func newSecretServer(t *testing.T, status int, contentType, body string) *secretServer {
	return newServerAt(t, http.MethodGet, "data", status, contentType, body)
}

// newMintServer answers the mint of the same path.
func newMintServer(t *testing.T, status int, contentType, body string) *secretServer {
	return newServerAt(t, http.MethodPost, "mint", status, contentType, body)
}

func newServerAt(t *testing.T, method, route string, status int, contentType, body string) *secretServer {
	t.Helper()
	s := &secretServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		s.lastQuery = r.URL.RawQuery
		if r.Method != method || r.URL.EscapedPath() != "/workload-secrets/api/v1/secrets/"+route+"/ci%2Fpayments" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *secretServer) client(t *testing.T) *Client {
	t.Helper()
	client, err := New(ClientOptions{BaseURL: s.URL + "/workload-secrets", TokenSource: staticToken("token")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

const staticSecretBody = `{"data":{"data":{"username":"app","password":"hunter2","port":5432,"tls":true,"note":null,
	"db":{"host":"db.internal","replicas":["a","b"]}},"metadata":{"version":3,"createdTime":"2026-11-01T10:00:00Z"}}}`

func TestGetSecret_ReturnsPlainValuesVersionAndTime(t *testing.T) {
	server := newSecretServer(t, http.StatusOK, "application/json", staticSecretBody)

	secret, err := server.client(t).GetSecret(context.Background(), "ci/payments")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}

	if secret.Path != "ci/payments" || secret.Version != 3 {
		t.Errorf("path %q version %d, want ci/payments version 3", secret.Path, secret.Version)
	}
	if want := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC); !secret.CreatedTime.Equal(want) {
		t.Errorf("created %v, want %v", secret.CreatedTime, want)
	}
	if secret.Data["password"] != "hunter2" || secret.Data["port"] != float64(5432) || secret.Data["tls"] != true {
		t.Errorf("primitives not plain: %#v %#v %#v", secret.Data["password"], secret.Data["port"], secret.Data["tls"])
	}
	// The generated client drops a key whose value is JSON null before GetSecret sees it. Pinned so a Kiota upgrade
	// that keeps it shows up here.
	if value, present := secret.Data["note"]; present {
		t.Errorf("null value = %#v, want the key absent (the generated client drops nulls)", value)
	}
	db, ok := secret.Data["db"].(map[string]any)
	if !ok || db["host"] != "db.internal" {
		t.Fatalf("nested object not kept as map[string]any: %#v", secret.Data["db"])
	}
	if replicas, ok := db["replicas"].([]any); !ok || len(replicas) != 2 || replicas[0] != "a" {
		t.Errorf("nested array not plain: %#v", db["replicas"])
	}
	if secret.Lease != nil {
		t.Errorf("a static secret has no lease, got %+v", secret.Lease)
	}
	if server.lastQuery != "" {
		t.Errorf("query %q, want none for the latest version", server.lastQuery)
	}
}

func TestGetSecretVersion_SendsTheVersion(t *testing.T) {
	server := newSecretServer(t, http.StatusOK, "application/json", staticSecretBody)

	if _, err := server.client(t).GetSecretVersion(context.Background(), "ci/payments", 2); err != nil {
		t.Fatalf("GetSecretVersion: %v", err)
	}
	if server.lastQuery != "version=2" {
		t.Errorf("query %q, want version=2", server.lastQuery)
	}
}

func TestMintSecret_ReadsADatabaseCredentialAndItsLease(t *testing.T) {
	body := `{"data":{"leaseId":"lease-42","expiresAt":"2026-11-03T19:15:00Z","credential":{"type":"database","username":"v_app_1","password":"x"}}}`
	server := newMintServer(t, http.StatusOK, "application/json", body)

	secret, err := server.client(t).MintSecret(context.Background(), "ci/payments")
	if err != nil {
		t.Fatalf("MintSecret: %v", err)
	}
	want := time.Date(2026, 11, 3, 19, 15, 0, 0, time.UTC)
	if secret.Lease == nil || secret.Lease.ID != "lease-42" || !secret.Lease.ExpiresAt.Equal(want) {
		t.Errorf("lease %+v, want lease-42 expiring %v", secret.Lease, want)
	}
	if secret.Data["type"] != "database" || secret.Data["username"] != "v_app_1" || secret.Data["password"] != "x" {
		t.Errorf("data %v, want the database type, username and password", secret.Data)
	}
	if len(secret.Data) != 3 {
		t.Errorf("data keys %v, want only type, username and password: the lease is on Lease", secret.keys())
	}
}

func TestMintSecret_ReadsAnAzureCredentialAndItsLease(t *testing.T) {
	body := `{"data":{"leaseId":"lease-43","expiresAt":"2026-11-03T19:15:00+00:00","credential":{"type":"azure","tenantId":"11111111-1111-1111-1111-111111111111",
		"clientId":"22222222-2222-2222-2222-222222222222","clientSecret":"s3cret"}}}`
	server := newMintServer(t, http.StatusOK, "application/json", body)

	secret, err := server.client(t).MintSecret(context.Background(), "ci/payments")
	if err != nil {
		t.Fatalf("MintSecret: %v", err)
	}
	if secret.Data["type"] != "azure" || secret.Data["tenantId"] != "11111111-1111-1111-1111-111111111111" ||
		secret.Data["clientId"] != "22222222-2222-2222-2222-222222222222" || secret.Data["clientSecret"] != "s3cret" {
		t.Errorf("data %v, want the azure type, tenant, client id and client secret", secret.Data)
	}
	if secret.Lease == nil || secret.Lease.ID != "lease-43" {
		t.Errorf("lease %+v, want lease-43", secret.Lease)
	}
}

func TestMintSecret_RefusesACredentialOfAnUnknownType(t *testing.T) {
	body := `{"data":{"leaseId":"lease-44","expiresAt":"2026-11-03T19:15:00Z","credential":{"type":"vault"}}}`
	server := newMintServer(t, http.StatusOK, "application/json", body)

	if _, err := server.client(t).MintSecret(context.Background(), "ci/payments"); err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Errorf("error %v, want one naming the unknown type", err)
	}
}

func TestGetSecret_DoesNotReadALeaseFromAStaticSecretsData(t *testing.T) {
	body := `{"data":{"data":{"leaseId":"not-a-lease","expiresAtUtc":"2026-11-03T19:15:00Z"},"metadata":{"version":1}}}`
	server := newSecretServer(t, http.StatusOK, "application/json", body)

	secret, err := server.client(t).GetSecret(context.Background(), "ci/payments")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if secret.Lease != nil {
		t.Errorf("a read has no lease, got %+v", secret.Lease)
	}
}

func TestMintSecret_IsRefusedForAStaticSecretWithAConflict(t *testing.T) {
	body := `{"status":409,"title":"Secret is not dynamic","errorCode":"secret_not_dynamic"}`
	server := newMintServer(t, http.StatusConflict, "application/problem+json", body)

	_, err := server.client(t).MintSecret(context.Background(), "ci/payments")

	var apiErr *APIError
	if !errors.Is(err, ErrConflict) || !errors.As(err, &apiErr) || apiErr.ErrorCode != "secret_not_dynamic" {
		t.Fatalf("err %v, want a conflict with errorCode secret_not_dynamic", err)
	}
}

func TestMintSecret_IsNotResentAfterAGatewayError(t *testing.T) {
	server := newMintServer(t, http.StatusBadGateway, "", "")

	if _, err := server.client(t).MintSecret(context.Background(), "ci/payments"); err == nil {
		t.Fatal("want an error for a 502")
	}
	if server.calls.Load() != 1 {
		t.Errorf("sent %d times, want 1: a resend could create another credential", server.calls.Load())
	}
}

func TestMintSecret_RejectsAnEmptyPath(t *testing.T) {
	server := newMintServer(t, http.StatusOK, "application/json", `{}`)

	if _, err := server.client(t).MintSecret(context.Background(), ""); err == nil || server.calls.Load() != 0 {
		t.Errorf("err %v after %d calls, want an error and no request", err, server.calls.Load())
	}
}

func TestGetSecret_TypedErrors(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
		sentinel    error
		errorCode   string
	}{
		{"bodyless 404", http.StatusNotFound, "", "", ErrNotFound, ""},
		{"problem 404", http.StatusNotFound, "application/problem+json", `{"status":404,"title":"secret_not_found","errorCode":"secret_not_found"}`, ErrNotFound, "secret_not_found"},
		{"403", http.StatusForbidden, "", "", ErrForbidden, ""},
		{"401", http.StatusUnauthorized, "", "", ErrUnauthorized, ""},
		{"409", http.StatusConflict, "application/problem+json", `{"status":409,"title":"engine_upgrade_required","errorCode":"engine_upgrade_required"}`, ErrConflict, "engine_upgrade_required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			server := newSecretServer(t, c.status, c.contentType, c.body)

			_, err := server.client(t).GetSecret(context.Background(), "ci/payments")
			if !errors.Is(err, c.sentinel) {
				t.Fatalf("err %v, want errors.Is %v", err, c.sentinel)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != c.status || apiErr.ErrorCode != c.errorCode {
				t.Errorf("APIError %+v, want status %d errorCode %q", apiErr, c.status, c.errorCode)
			}
		})
	}
}

func TestGetSecret_ErrorTextNeverCarriesTheResponseBody(t *testing.T) {
	body := `{"status":409,"title":"engine_upgrade_required","errorCode":"engine_upgrade_required","detail":"hunter2 leaked"}`
	server := newSecretServer(t, http.StatusConflict, "application/problem+json", body)

	_, err := server.client(t).GetSecret(context.Background(), "ci/payments")
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error %q must not quote the response body", err)
	}
}

func TestGetSecret_IsRetriedOnABadGateway(t *testing.T) {
	server := newSecretServer(t, http.StatusBadGateway, "", "")

	if _, err := server.client(t).GetSecret(context.Background(), "ci/payments"); err == nil {
		t.Fatal("want an error for a 502")
	}
	if server.calls.Load() < 2 {
		t.Errorf("sent %d times, want a retry: reading changes nothing", server.calls.Load())
	}
}

func TestGetSecret_RejectsAnEmptyPath(t *testing.T) {
	client, err := New(ClientOptions{BaseURL: "http://127.0.0.1:1", TokenSource: staticToken("token")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.GetSecret(context.Background(), ""); err == nil {
		t.Error("want an error for an empty path")
	}
}

func TestSecret_PrintingNeverShowsValues(t *testing.T) {
	server := newSecretServer(t, http.StatusOK, "application/json", staticSecretBody)
	secret, err := server.client(t).GetSecret(context.Background(), "ci/payments")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}

	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("read", "secret", secret)
	outputs := map[string]string{
		"%v":   fmt.Sprintf("%v", secret),
		"%+v":  fmt.Sprintf("%+v", secret),
		"%#v":  fmt.Sprintf("%#v", secret),
		"%s":   fmt.Sprintf("%s", secret),
		"slog": logged.String(),
	}
	for verb, out := range outputs {
		if strings.Contains(out, "hunter2") || strings.Contains(out, "db.internal") {
			t.Errorf("%s prints a value: %s", verb, out)
		}
		if !strings.Contains(out, "password") || !strings.Contains(out, "ci/payments") {
			t.Errorf("%s should show the path and key names: %s", verb, out)
		}
	}
}
