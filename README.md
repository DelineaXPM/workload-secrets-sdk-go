# Delinea Workload Secrets Vault SDK for Go

Read secrets from Delinea Workload Secrets Vault in a Go application.

- Go 1.26 or later.
- Module `github.com/DelineaXPM/workload-secrets-sdk-go`, package `workloadsecrets`:

  ```
  go get github.com/DelineaXPM/workload-secrets-sdk-go
  ```
- Reference documentation and examples: [pkg.go.dev](https://pkg.go.dev/github.com/DelineaXPM/workload-secrets-sdk-go).

## Quick start

```go
import "github.com/DelineaXPM/workload-secrets-sdk-go"

client, err := workloadsecrets.New(workloadsecrets.ClientOptions{
	BaseURL:       "https://example.delinea.app/workload-secrets",
	TokenEndpoint: "https://example.delinea.app/identity/oauth2/token/xpmplatform",
	ClientID:      "my-service-user@example",
	ClientSecret:  clientSecret, // from your secret store or environment, never from source code
})
if err != nil {
	return err
}

secret, err := client.GetSecret(ctx, "ci/payments/api")
if err != nil {
	return err
}

apiKey := secret.Data["apiKey"].(string)
```

`secret.Data` holds the secret's values as plain Go values, the way `encoding/json` decodes JSON: `string`, `bool`,
`float64`, `[]any` and `map[string]any`. Use the values in your application. Never print or log them.

`secret.Version` and `secret.CreatedTime` describe the version you read. To read an older version, use
`client.GetSecretVersion(ctx, path, version)`.

The client is safe to use from many goroutines. Create one and reuse it.

## Dynamic secrets

A dynamic secret holds no stored values. Each call to `MintSecret` creates a new credential with a lease, and the
credential stops working when the lease expires. Dynamic secrets are available from the December 10, 2026 private
preview.

```go
credential, err := client.MintSecret(ctx, "ci/payments/pg-db")
if err != nil {
	return err
}

username := credential.Data["username"].(string)
password := credential.Data["password"].(string)
expiresAt := credential.Lease.ExpiresAt // a time.Time
```

`credential.Data["type"]` says which values it holds:

| `type`     | Values                                   |
| ---------- | ---------------------------------------- |
| `database` | `username`, `password`                   |
| `azure`    | `tenantId`, `clientId`, `clientSecret`   |

Mint once and reuse the credential until its lease is close to expiring: every call creates another credential.
Reading a dynamic secret with `GetSecret` fails with `ErrConflict`, and so does minting a secret that is not dynamic.

## Bring your own token

Instead of a client ID and secret, give the client a `TokenSource`: any value with a `Token` method that returns an
access token, without the `Bearer ` prefix.

```go
type myTokenSource struct{}

func (myTokenSource) Token(ctx context.Context) (string, error) {
	return getTokenFromMyPlatform(ctx) // cache it, and refresh it before it expires
}

client, err := workloadsecrets.New(workloadsecrets.ClientOptions{
	BaseURL:     "https://example.delinea.app/workload-secrets",
	TokenSource: myTokenSource{},
})
```

The SDK calls `Token` once per request, so cache the token in your source. Add an `Invalidate(rejected string)`
method if your source can renew a token early: when the API rejects a token with 401, the SDK calls it, asks for a
token again, and resends the request once if the token changed.

## Errors

| Error             | When                                                                                 |
| ----------------- | ------------------------------------------------------------------------------------ |
| `ErrNotFound`     | 404: no secret at that path or version                                               |
| `ErrForbidden`    | 403: signed in, but not allowed. Check the roles and Workload Secrets Vault policies |
| `ErrUnauthorized` | 401: the credentials or token were not accepted                                      |
| `ErrConflict`     | 409: for example, reading a dynamic secret, which must be minted                     |

Test for them with `errors.Is`:

```go
secret, err := client.GetSecret(ctx, path)
if errors.Is(err, workloadsecrets.ErrNotFound) {
	// no secret at that path
}
```

Every error the API returns is an `*APIError`. Use `errors.As` to read its `StatusCode`, `ErrorCode` and `Title`.
Any other error means the call could not complete: the API was unreachable, the call timed out, or sign-in failed.
No error message contains a response body or a secret value.

## Behavior

- **Retries.** Reads are retried on 408, 429, 502, 503 and 504 and on connection failures, up to 4 attempts, with
  exponential backoff and jitter. `Retry-After` is honoured up to 30 seconds. A request that changes data, such
  as a mint, is retried only when the API proves it did nothing: the connection was never made, 429, or 503 with `Retry-After`.
- **Timeouts.** 15 seconds per attempt and 60 seconds for the whole call, including retries. Change them with
  `Behavior.PerAttemptTimeout` and `Behavior.TotalTimeout`. The `ctx` you pass can end a call sooner.
- **Redirects.** 307 and 308 are followed to the same host only, so your token is never sent to another host.
- **HTTPS only.** `New` refuses a plain `http://` address, except `localhost`, `127.0.0.1` or `::1` for local testing,
  so a token or the client secret is never sent in clear text.
- **Logging.** Set `Logger` to an `*slog.Logger` to get a debug record for each retry: method, path, attempt, wait,
  status and error text, never headers or bodies.

## TLS and proxies

By default the SDK sends requests through `http.DefaultTransport`, which honours `HTTPS_PROXY` and `NO_PROXY` and
verifies the server certificate against the operating system's trusted certificates. If your network inspects TLS
traffic, pass a transport that trusts your company's certificate:

```go
pem, err := os.ReadFile("/path/to/company-ca.pem")
if err != nil {
	return err
}
roots, err := x509.SystemCertPool()
if err != nil {
	return err
}
roots.AppendCertsFromPEM(pem)

transport := http.DefaultTransport.(*http.Transport).Clone()
transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}

client, err := workloadsecrets.New(workloadsecrets.ClientOptions{
	// ...
	Transport: transport,
})
```

## Security

- Printing a `Secret` (with `fmt` or `log/slog`) shows its path, version and key names, never its values.
- Printing `ClientOptions` (with `fmt` or `log/slog`) never shows the client secret.
- Errors never carry a response body or a secret value.
- Each statement above is checked by the SDK's tests (`secret_test.go`, `https_only_test.go`).

## The full API

`client.API()` is the generated client for the whole Workload Secrets Vault API, for calls this SDK does not wrap. It uses
the same credentials, retries and timeouts.

## Development

```
go build ./...
go test ./...
go vet ./...
```

The `generated` package is produced by `scripts/regen-go-client.sh` from the API contract. Do not edit it by hand.
