// Package workloadsecrets reads secrets from Delinea Workload Secrets Vault in a Go application.
//
// Create one [Client] with [New] and reuse it: it is safe for concurrent use.
//
//	client, err := workloadsecrets.New(workloadsecrets.ClientOptions{
//		BaseURL:       "https://example.delinea.app/workload-secrets",
//		TokenEndpoint: "https://example.delinea.app/identity/oauth2/token/xpmplatform",
//		ClientID:      "my-service-user@example",
//		ClientSecret:  os.Getenv("WS_CLIENT_SECRET"), // never from source code
//	})
//	if err != nil {
//		return err
//	}
//	secret, err := client.GetSecret(ctx, "ci/payments/api")
//	if err != nil {
//		return err
//	}
//	apiKey := secret.Data["apiKey"].(string)
//
// # Reading and minting
//
// [Client.GetSecret] reads the latest version of a secret and [Client.GetSecretVersion] reads one version.
// [Client.MintSecret] creates a new credential for a dynamic secret and returns it with its [Lease]; every call
// creates another credential, so mint once and reuse it until the lease is close to expiring.
// Dynamic secrets are available from the December 10, 2026 private preview.
//
// # Signing in
//
// By default the client signs in with a client ID and secret at TokenEndpoint. To use a token you already have,
// for example from workload identity federation, set [ClientOptions.TokenSource] instead.
//
// # Errors
//
// Failures from the API are [*APIError] and match [ErrNotFound], [ErrForbidden], [ErrUnauthorized] or
// [ErrConflict] with [errors.Is]. No error message contains a response body or a secret value.
//
// # Security
//
//   - Only https addresses are accepted, except plain http to localhost, 127.0.0.1 or ::1 for local testing,
//     so a token or the client secret is never sent in clear text.
//   - Printing a [Secret] shows its path, version and key names, never its values.
//   - Printing [ClientOptions] never shows the client secret.
//   - Redirects are followed to the same host only, so a token never reaches another host.
//
// # Behavior
//
// Reads are retried on 408, 429, 502, 503, 504 and connection failures, up to 4 attempts with backoff and jitter;
// a mint is retried only when the API proves it did nothing. Each attempt is limited to 15 seconds and the whole
// call to 60 seconds; change them with [ClientOptions.Behavior].
//
// # The full API
//
// [Client.API] returns the generated client for every Workload Secrets Vault API operation, with the same credentials,
// retries and timeouts.
package workloadsecrets
