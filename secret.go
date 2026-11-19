package workloadsecrets

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	generated "github.com/DelineaXPM/workload-secrets-sdk-go/generated"
	"github.com/DelineaXPM/workload-secrets-sdk-go/generated/api"
	"github.com/DelineaXPM/workload-secrets-sdk-go/generated/models"
	"github.com/google/uuid"
)

// Client reads secrets and mints dynamic credentials with one call each. Anything else the API offers is on API(), the generated client, which uses
// the same credentials, retries and timeouts.
type Client struct {
	api *generated.WorkloadSecretsApiClient
}

// New builds a Client from options. It wires the same transport chain as NewClient: tenant header, retries that obey
// the API's retry-safety flags, the bearer token and same-origin redirects.
func New(options ClientOptions) (*Client, error) {
	api, err := NewClient(options)
	if err != nil {
		return nil, err
	}
	return &Client{api: api}, nil
}

// API returns the generated client, for the operations Client has no call for.
func (c *Client) API() *generated.WorkloadSecretsApiClient { return c.api }

// Secret is one version of a secret, or the credential a mint created. Printing it (fmt, or slog) shows the path,
// version and key names, never the values: read a value from Data explicitly.
type Secret struct {
	Path string
	// Version and CreatedTime describe the version a read returned. They are zero for a minted credential.
	Version     int
	CreatedTime time.Time
	// Data holds the secret's values as plain Go values, the way encoding/json decodes JSON. Nested objects are kept; a
	// top-level key whose value is JSON null is absent. A minted credential holds "type" ("database" or "azure") and
	// its strings: username and password, or tenantId, clientId and clientSecret.
	Data map[string]any
	// Lease is set by MintSecret: the credential in Data stops working at Lease.ExpiresAt. Nil for a static secret.
	Lease *Lease
}

// Lease identifies the credential a mint created, and when it expires.
type Lease struct {
	ID        string
	ExpiresAt time.Time
}

// GetSecret reads the latest version of the secret at path. Reading changes nothing. A dynamic secret holds no values
// to read: the API refuses it with a conflict, and MintSecret creates its credential. Failures from the API are
// *APIError and match ErrNotFound, ErrForbidden, ErrUnauthorized or ErrConflict with errors.Is.
func (c *Client) GetSecret(ctx context.Context, path string) (*Secret, error) {
	return c.getSecret(ctx, path, nil)
}

// GetSecretVersion reads one version of the secret at path. Otherwise it behaves like GetSecret.
func (c *Client) GetSecretVersion(ctx context.Context, path string, version int) (*Secret, error) {
	v := int32(version)
	return c.getSecret(ctx, path, &v)
}

func (c *Client) getSecret(ctx context.Context, path string, version *int32) (*Secret, error) {
	if path == "" {
		return nil, errors.New("workload secrets: read: the path is empty")
	}
	var config *api.V1SecretsDataWithPathItemRequestBuilderGetRequestConfiguration
	if version != nil {
		config = &api.V1SecretsDataWithPathItemRequestBuilderGetRequestConfiguration{
			QueryParameters: &api.V1SecretsDataWithPathItemRequestBuilderGetQueryParameters{Version: version},
		}
	}
	resp, err := c.api.Api().V1().Secrets().Data().ByPath(path).Get(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("workload secrets: read %q: %w", path, asAPIError(err))
	}
	return secretFrom(path, "read", resp)
}

// MintSecret creates a credential for the dynamic secret at path and returns it with its Lease. Every call creates
// another credential, so the call is never resent once the request may have reached the API (see the retry rules).
// A secret that is not dynamic is refused with a conflict. Dynamic secrets are available from the December 10, 2026
// private preview. Failures from the API are *APIError and match ErrNotFound, ErrForbidden, ErrUnauthorized or
// ErrConflict with errors.Is.
func (c *Client) MintSecret(ctx context.Context, path string) (*Secret, error) {
	if path == "" {
		return nil, errors.New("workload secrets: mint: the path is empty")
	}
	resp, err := c.api.Api().V1().Secrets().Mint().ByPath(path).Post(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("workload secrets: mint %q: %w", path, asAPIError(err))
	}
	return mintedFrom(path, resp)
}

// mintedFrom builds a Secret from a mint response. The credential's type decides which values Data holds; a type this
// SDK does not know is an error, because its secret values would be unreadable.
func mintedFrom(path string, resp models.MintResponseable) (*Secret, error) {
	if resp == nil || resp.GetData() == nil {
		return nil, fmt.Errorf("workload secrets: mint %q: the response has no data", path)
	}

	lease := resp.GetData()
	credential := lease.GetCredential()
	if credential == nil {
		return nil, fmt.Errorf("workload secrets: mint %q: the response has no credential", path)
	}

	secret := &Secret{Path: path, Data: map[string]any{}}
	switch typed := credential.(type) {
	case models.DatabaseCredentialable:
		secret.Data["type"] = "database"
		secret.Data["username"] = derefOr(typed.GetUsername())
		secret.Data["password"] = derefOr(typed.GetPassword())
	case models.AzureCredentialable:
		secret.Data["type"] = "azure"
		secret.Data["tenantId"] = uuidString(typed.GetTenantId())
		secret.Data["clientId"] = uuidString(typed.GetClientId())
		secret.Data["clientSecret"] = derefOr(typed.GetClientSecret())
	default:
		return nil, fmt.Errorf("workload secrets: mint %q: the response carries a credential of an unknown type %q", path, derefOr(credential.GetTypeEscaped()))
	}

	secret.Lease = leaseFrom(lease)
	return secret, nil
}

func uuidString(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return id.String()
}

// secretFrom builds a Secret from a secret response; operation names the call in errors.
func secretFrom(path, operation string, resp models.SecretResponseable) (*Secret, error) {
	if resp == nil || resp.GetData() == nil {
		return nil, fmt.Errorf("workload secrets: %s %q: the response has no data", operation, path)
	}

	payload := resp.GetData()
	secret := &Secret{Path: path, Data: map[string]any{}}
	if raw := payload.GetData(); raw != nil {
		for key, value := range raw.GetAdditionalData() {
			secret.Data[key] = plain(value)
		}
	}
	if metadata := payload.GetMetadata(); metadata != nil {
		if v := metadata.GetVersion(); v != nil {
			secret.Version = int(*v)
		}
		if created := metadata.GetCreatedTime(); created != nil {
			secret.CreatedTime = *created
		}
	}
	return secret, nil
}

// plain turns a value as the generated client decodes it (pointers to primitives, nested maps and slices of them)
// into the plain value encoding/json would produce, so callers never dereference.
func plain(value any) any {
	switch v := value.(type) {
	case nil:
		return nil
	case *string:
		return derefOr(v)
	case *bool:
		return derefOr(v)
	case *float64:
		return derefOr(v)
	case *float32:
		return number(v)
	case *int64:
		return number(v)
	case *int32:
		return number(v)
	case *int:
		return number(v)
	case *uint8:
		return number(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, element := range v {
			out[key] = plain(element)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, element := range v {
			out[i] = plain(element)
		}
		return out
	default:
		return v
	}
}

func derefOr[T any](value *T) any {
	if value == nil {
		return nil
	}
	return *value
}

func number[T float32 | int64 | int32 | int | uint8](value *T) any {
	if value == nil {
		return nil
	}
	return float64(*value)
}

// leaseFrom reads the lease a mint returns: the lease id and the time its credential stops working. Both are required by
// the contract; a response without them has no lease.
func leaseFrom(lease models.MintedLeaseable) *Lease {
	id := lease.GetLeaseId()
	expires := lease.GetExpiresAt()
	if id == nil || *id == "" || expires == nil {
		return nil
	}
	return &Lease{ID: *id, ExpiresAt: *expires}
}

// String shows the path, version and key names, never a value.
func (s *Secret) String() string {
	if s == nil {
		return "<nil secret>"
	}
	return fmt.Sprintf("secret %s version %d keys [%s]", s.Path, s.Version, strings.Join(s.keys(), " "))
}

// GoString keeps %#v from printing values.
func (s *Secret) GoString() string { return s.String() }

// LogValue keeps slog from printing values.
func (s *Secret) LogValue() slog.Value {
	if s == nil {
		return slog.StringValue("<nil secret>")
	}
	return slog.GroupValue(slog.String("path", s.Path), slog.Int("version", s.Version), slog.Any("keys", s.keys()))
}

func (s *Secret) keys() []string {
	return slices.Sorted(maps.Keys(s.Data))
}
