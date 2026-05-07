package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// capturedRequest is delivered from the test handler to the test
// goroutine via a buffered channel so the send-receive establishes
// happens-before for the captured fields. Avoids relying on net/http
// internals to synchronize handler-goroutine writes with test reads.
type capturedRequest struct {
	method string
	path   string
	body   map[string]any
}

// TestHTTPResolverSendsAPIKeyField guards against the regression where the
// kvstore was sending {"token": ...} while controlplane's
// /api/internal/key-identity expects {"api_key": ...}. Fail this test and
// production identity lookups break silently with a 400 from controlplane.
func TestHTTPResolverSendsAPIKeyField(t *testing.T) {
	captured := make(chan capturedRequest, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]any
		json.Unmarshal(body, &parsed)
		captured <- capturedRequest{method: r.Method, path: r.URL.Path, body: parsed}
		json.NewEncoder(w).Encode(Identity{UserID: "user_x", OrgID: "org_y"})
	}))
	defer srv.Close()

	id, err := NewHTTPResolver(srv.URL).Resolve(context.Background(), "ak_abc123")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	got := <-captured
	if got.method != http.MethodPost {
		t.Errorf("method: got %q, want POST", got.method)
	}
	if got.path != "/api/internal/key-identity" {
		t.Errorf("path: got %q, want /api/internal/key-identity", got.path)
	}
	if v := got.body["api_key"]; v != "ak_abc123" {
		t.Errorf("api_key field: got %v, want %q", v, "ak_abc123")
	}
	if _, ok := got.body["token"]; ok {
		t.Errorf("legacy token field should not be sent: %v", got.body)
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
