# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately. Do not open a public GitHub issue.
Use this repository's
[private vulnerability reporting form](https://github.com/DelineaXPM/workload-secrets-sdk-go/security/advisories/new),
the **Report issue** link in Delinea's
[Responsible Disclosure](https://trust.delinea.com/) portal, or your Delinea
private preview contact.

Never include a real secret, client secret or access token in a report.

## Supported versions

The SDK is in preview. Only the latest release receives fixes; upgrade to it
before reporting a problem.

## How the SDK protects your credentials

- Only `https://` addresses are accepted, except plain `http://` to
  `localhost`, `127.0.0.1` or `::1` for local testing, so an access token or
  client secret is never sent in clear text.
- Redirects are followed to the same host only, so a token never reaches
  another host.
- Printing a `Secret` shows its path, version and key names, never its values.
  Printing `ClientOptions` never shows the client secret.
- No error message contains a response body or a secret value.
- A request that changes data, such as a mint, is never sent twice unless the
  API proves the first attempt did nothing.

Each statement above is checked by the SDK's tests.

## Supply chain

Direct dependencies: the Microsoft Kiota runtime libraries
(`github.com/microsoft/kiota-*-go`), `golang.org/x/oauth2` and
`github.com/google/uuid`. Every release is checked before it is published:
build, `go vet` and the tests; [`govulncheck`](https://go.dev/doc/security/vuln/),
which reports vulnerabilities in code the SDK actually calls; a secret scan;
and dependency vulnerability scanning.

The `go` directive in `go.mod` is the minimum supported Go version.

## Releases

This SDK is distributed as tagged Go module source. Releases are built and
reviewed in Delinea's internal repository and published here; tags are
immutable once published.
