package workloadsecrets

import "net/http"

// tenantHeaderName is the header the API uses to resolve the calling tenant.
const tenantHeaderName = "X-MT-SecondaryId"

// tenantHeaderTransport stamps every outgoing request with the configured tenant's X-MT-SecondaryId header.
type tenantHeaderTransport struct {
	tenantID string
	next     http.RoundTripper
}

func (t *tenantHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set(tenantHeaderName, t.tenantID)
	return t.next.RoundTrip(req)
}
