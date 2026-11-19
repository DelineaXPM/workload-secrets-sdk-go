package workloadsecrets

import (
	"net/http"
	"runtime/debug"
)

// sdkModulePath is this module's path, used to find its version in the build info of the program that imports it.
const sdkModulePath = "github.com/DelineaXPM/workload-secrets-sdk-go"

// userAgent identifies the SDK and its version on every request.
func userAgent() string {
	version := "0.0.0"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == sdkModulePath && dep.Version != "" && dep.Version != "(devel)" {
				version = dep.Version
			}
		}
	}
	return "delinea-workloadsecrets-sdk-go/" + version
}

// userAgentTransport sets the SDK's User-Agent on every outgoing request.
type userAgentTransport struct {
	value string
	next  http.RoundTripper
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", t.value)
	return t.next.RoundTrip(req)
}
