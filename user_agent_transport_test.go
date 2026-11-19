package workloadsecrets

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUserAgentTransport_SetsTheSDKUserAgent(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
	}))
	defer server.Close()

	client := &http.Client{Transport: &userAgentTransport{value: userAgent(), next: http.DefaultTransport}}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()

	if !strings.HasPrefix(got, "delinea-workloadsecrets-sdk-go/") {
		t.Errorf("User-Agent = %q, want the SDK product", got)
	}
}
