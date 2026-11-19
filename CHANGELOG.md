# Changelog

## v0.2.0-preview.1 (unreleased)

The first release published on GitHub.

### Breaking

- The module path is now `github.com/DelineaXPM/workload-secrets-sdk-go`
  and the package is `workloadsecrets` (previously `publicapi`). Update your
  imports:

  ```go
  import "github.com/DelineaXPM/workload-secrets-sdk-go"
  ```

### Security

- Only `https://` addresses are accepted, except plain `http://` to
  `localhost`, `127.0.0.1` or `::1` for local testing.
- Printing `ClientOptions` hides the client secret.

### Added

- Package documentation and examples on
  [pkg.go.dev](https://pkg.go.dev/github.com/DelineaXPM/workload-secrets-sdk-go).

### Included from earlier previews

- `Client.GetSecret` and `Client.GetSecretVersion` read a secret.
- `Client.MintSecret` creates a credential for a dynamic secret and returns
  its `Lease`. Dynamic secrets are available from the December 10, 2026
  private preview.
- Sign in with a client ID and secret, or bring your own token with
  `ClientOptions.TokenSource`.
- `ErrNotFound`, `ErrForbidden`, `ErrUnauthorized`, `ErrConflict` and
  `*APIError` for error handling.
- Retries with backoff, per-attempt and total timeouts, and same-host
  redirects.
- `Client.API` for every Workload Secrets Vault API operation.
