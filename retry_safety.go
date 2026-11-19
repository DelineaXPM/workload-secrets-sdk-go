package workloadsecrets

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	generated "github.com/DelineaXPM/workload-secrets-sdk-go/generated"
)

// operationSafety decides from the API contract's x-retry-safe flags (generated.RetrySafetyTable) whether a request may
// be sent again after the server may have received it. The flag is per operation, not per HTTP method: the secret read
// is a GET, but reading a dynamic secret creates a credential, so the contract marks it unsafe. A request that matches
// no operation falls back to the HTTP method.
type operationSafety struct {
	basePath   string
	operations []operationPattern
}

type operationPattern struct {
	method    string
	path      *regexp.Regexp
	retrySafe bool
}

// newOperationSafety compiles the generated table. baseURL is the client's BaseURL; its path (for example
// "/workload-secrets") is removed from a request path before matching, because the templates start at "/api".
func newOperationSafety(baseURL string) operationSafety {
	basePath := ""
	if parsed, err := url.Parse(baseURL); err == nil {
		basePath = strings.TrimRight(parsed.EscapedPath(), "/")
	}
	table := generated.RetrySafetyTable()
	operations := make([]operationPattern, 0, len(table))
	for _, operation := range table {
		operations = append(operations, operationPattern{
			method:    operation.Method,
			path:      templatePattern(operation.PathTemplate),
			retrySafe: operation.RetrySafe,
		})
	}
	return operationSafety{basePath: basePath, operations: operations}
}

// templatePattern turns a path template such as "/api/v1/pki/ca/{name}/crl" into an anchored expression. A parameter
// matches one segment; a parameter that ends the template matches the rest of the path, because a secret or key path
// may contain "/".
func templatePattern(template string) *regexp.Regexp {
	segments := strings.Split(strings.TrimPrefix(template, "/"), "/")
	var pattern strings.Builder
	pattern.WriteString("^")
	for i, segment := range segments {
		pattern.WriteString("/")
		switch {
		case !strings.HasPrefix(segment, "{"):
			pattern.WriteString(regexp.QuoteMeta(segment))
		case i == len(segments)-1:
			pattern.WriteString(".+")
		default:
			pattern.WriteString("[^/]+")
		}
	}
	pattern.WriteString("$")
	return regexp.MustCompile(pattern.String())
}

// retrySafe reports whether req may be sent again after the server may have received it. The path is matched in its
// escaped form, so an encoded "/" inside a parameter stays inside its segment. When several operations match, the
// request is safe only if every one of them is.
func (s operationSafety) retrySafe(req *http.Request) bool {
	path := req.URL.EscapedPath()
	if trimmed, ok := strings.CutPrefix(path, s.basePath); ok && s.basePath != "" {
		path = trimmed
	}
	matched := false
	for _, operation := range s.operations {
		if operation.method != req.Method || !operation.path.MatchString(path) {
			continue
		}
		if !operation.retrySafe {
			return false
		}
		matched = true
	}
	return matched || isSafeMethod(req.Method)
}
