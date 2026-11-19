package workloadsecrets_test

// These examples appear on the package's documentation page. `go test` compiles every one of them, so they always
// match the SDK; they have no "Output:" comment, so they are not run, because they need a real Workload Secrets tenant.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/DelineaXPM/workload-secrets-sdk-go"
)

// Sign in with a client ID and secret. The secret comes from the environment, never from source code.
func ExampleNew() {
	client, err := workloadsecrets.New(workloadsecrets.ClientOptions{
		BaseURL:       "https://example.delinea.app/workload-secrets",
		TokenEndpoint: "https://example.delinea.app/identity/oauth2/token/xpmplatform",
		ClientID:      "my-service-user@example",
		ClientSecret:  os.Getenv("WS_CLIENT_SECRET"),
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = client // create one client and reuse it
}

// Read the latest version of a secret and use one of its values.
func ExampleClient_GetSecret() {
	client := newClient()

	secret, err := client.GetSecret(context.Background(), "ci/payments/api")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(secret) // safe: shows the path, version and key names, never the values

	apiKey := secret.Data["apiKey"].(string)
	_ = apiKey // use the value; never print or log it
}

// Read one version of a secret.
func ExampleClient_GetSecretVersion() {
	client := newClient()

	secret, err := client.GetSecretVersion(context.Background(), "ci/payments/api", 2)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(secret.Version, secret.CreatedTime.Format(time.RFC3339))
}

// Mint a database credential from a dynamic secret. Every call creates another credential, so mint once and reuse it
// until its lease is close to expiring. Dynamic secrets are available from the December 10, 2026 private preview.
func ExampleClient_MintSecret() {
	client := newClient()

	credential, err := client.MintSecret(context.Background(), "ci/payments/pg-db")
	if err != nil {
		log.Fatal(err)
	}
	if credential.Data["type"] == "database" {
		username := credential.Data["username"].(string)
		password := credential.Data["password"].(string)
		_, _ = username, password // connect to the database with them
	}
	fmt.Println("expires", credential.Lease.ExpiresAt.Format(time.RFC3339))
}

// Use a token you already have, for example from workload identity federation, instead of a client ID and secret.
func ExampleClientOptions_tokenSource() {
	client, err := workloadsecrets.New(workloadsecrets.ClientOptions{
		BaseURL:     "https://example.delinea.app/workload-secrets",
		TokenSource: platformTokenSource{},
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = client
}

// platformTokenSource is a TokenSource. The SDK calls Token once per request, so a real one caches the token and
// refreshes it before it expires.
type platformTokenSource struct{}

func (platformTokenSource) Token(ctx context.Context) (string, error) {
	token, err := os.ReadFile("/var/run/secrets/tokens/workload-secrets") // a token file your platform keeps fresh
	return string(token), err
}

// Handle the usual failures with errors.Is, and read the details of any API error with errors.As.
func Example_errors() {
	client := newClient()

	_, err := client.GetSecret(context.Background(), "ci/payments/api")
	switch {
	case err == nil:
		// use the secret
	case errors.Is(err, workloadsecrets.ErrNotFound):
		fmt.Println("no secret at that path")
	case errors.Is(err, workloadsecrets.ErrForbidden):
		fmt.Println("signed in, but a policy does not allow this read")
	default:
		var apiErr *workloadsecrets.APIError
		if errors.As(err, &apiErr) {
			fmt.Println(apiErr.StatusCode, apiErr.ErrorCode)
		}
		log.Fatal(err)
	}
}

func newClient() *workloadsecrets.Client {
	client, err := workloadsecrets.New(workloadsecrets.ClientOptions{
		BaseURL:       os.Getenv("WS_BASE_URL"),
		TokenEndpoint: os.Getenv("WS_TOKEN_ENDPOINT"),
		ClientID:      os.Getenv("WS_CLIENT_ID"),
		ClientSecret:  os.Getenv("WS_CLIENT_SECRET"),
	})
	if err != nil {
		log.Fatal(err)
	}
	return client
}
