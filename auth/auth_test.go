package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHTTPResolverSendsAPIKeyField guards against the regression where the
// kvstore was sending {"token": ...} while controlplane's
// /api/shim/identity expects {"api_key": ...}. Fail this test and
// production identity lookups break silently with a 400 from controlplane.
func TestHTTPResolverSendsAPIKeyField(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &gotBody)
		json.NewEncoder(w).Encode(Identity{UserID: "user_x", OrgID: "org_y"})
	}))
	defer srv.Close()

	id, err := NewHTTPResolver(srv.URL).Resolve(context.Background(), "ak_abc123")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method: got %q, want POST", gotMethod)
	}
	if gotPath != "/api/shim/identity" {
		t.Errorf("path: got %q, want /api/shim/identity", gotPath)
	}
	if got := gotBody["api_key"]; got != "ak_abc123" {
		t.Errorf("api_key field: got %v, want %q", got, "ak_abc123")
	}
	if _, ok := gotBody["token"]; ok {
		t.Errorf("legacy token field should not be sent: %v", gotBody)
	}
	if id.UserID != "user_x" || id.OrgID != "org_y" {
		t.Errorf("identity: got %+v", id)
	}
}

func TestHTTPResolverMaps401ToInvalidToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := NewHTTPResolver(srv.URL).Resolve(context.Background(), "bad")
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

func TestHTTPResolverMaps5xxToUpstreamUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := NewHTTPResolver(srv.URL).Resolve(context.Background(), "ak")
	if !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("got %v, want ErrUpstreamUnavailable", err)
	}
}

func TestHTTPResolverMissingUserIDIsUpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	_, err := NewHTTPResolver(srv.URL).Resolve(context.Background(), "ak")
	if !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("got %v, want ErrUpstreamUnavailable", err)
	}
}
