// Package auth resolves controlplane API keys to the owning Clerk user
// or organization by calling controlplane's /api/shim/identity endpoint.
// The returned identity is used by the item handler to namespace R2
// storage keys per tenant.
package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Identity is the resolved owner of an API key. Exactly one of OrgID or
// UserID is populated downstream when picking the storage prefix — org
// wins when present, user is the fallback.
type Identity struct {
	UserID string `json:"user_id"`
	OrgID  string `json:"org_id,omitempty"`
}

// Resolver looks up an API key's owning identity.
type Resolver interface {
	Resolve(ctx context.Context, apiKey string) (Identity, error)
}

// ErrInvalidToken is returned when controlplane rejects the API key
// (HTTP 401). Callers should map this to 401 for the kvstore client.
var ErrInvalidToken = errors.New("invalid api key")

// ErrUpstreamUnavailable is returned for transport errors or non-401
// non-2xx responses from controlplane. Callers should map this to 502.
var ErrUpstreamUnavailable = errors.New("identity service unavailable")

// HTTPResolver calls controlplane's POST /api/shim/identity.
type HTTPResolver struct {
	baseURL string
	client  *http.Client
}

// NewHTTPResolver constructs a Resolver pointed at controlplane's base
// URL (e.g. "https://controlplane.tinfoil.sh"). Trailing slashes are
// trimmed.
func NewHTTPResolver(baseURL string) *HTTPResolver {
	return &HTTPResolver{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: 5 * time.Second},
	}
}

type identityRequest struct {
	APIKey string `json:"api_key"`
}

func (r *HTTPResolver) Resolve(ctx context.Context, apiKey string) (Identity, error) {
	body, err := json.Marshal(identityRequest{APIKey: apiKey})
	if err != nil {
		return Identity{}, fmt.Errorf("marshal identity request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.baseURL+"/api/shim/identity", bytes.NewReader(body))
	if err != nil {
		return Identity{}, fmt.Errorf("build identity request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrUpstreamUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return Identity{}, ErrInvalidToken
	}
	if resp.StatusCode/100 != 2 {
		// Drain a small amount for context in errors without bloating logs.
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return Identity{}, fmt.Errorf("%w: status %d: %s", ErrUpstreamUnavailable, resp.StatusCode, strings.TrimSpace(string(preview)))
	}

	var id Identity
	if err := json.NewDecoder(resp.Body).Decode(&id); err != nil {
		return Identity{}, fmt.Errorf("%w: decode response: %v", ErrUpstreamUnavailable, err)
	}
	if id.UserID == "" {
		return Identity{}, fmt.Errorf("%w: missing user_id in response", ErrUpstreamUnavailable)
	}
	return id, nil
}
