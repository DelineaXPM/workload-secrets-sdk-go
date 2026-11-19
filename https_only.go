package workloadsecrets

import (
	"fmt"
	"net/url"
	"strings"
)

// loopbackHosts may be reached over plain http, for local testing. Every other host needs https.
var loopbackHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}

// requireHTTPS refuses an address that would send credentials or secrets in clear text: anything but https, except
// http to a loopback host. name is the option the address came from, for the error message.
func requireHTTPS(raw, name string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("workload secrets: %s is not a valid http or https address", name)
	}
	if !secureOrLoopback(u) {
		return fmt.Errorf("workload secrets: %s must use https: credentials and secrets would be sent in clear text", name)
	}
	return nil
}

// secureOrLoopback reports whether a request to u keeps a token off the network in clear text.
func secureOrLoopback(u *url.URL) bool {
	return strings.EqualFold(u.Scheme, "https") || loopbackHosts[strings.ToLower(u.Hostname())]
}
