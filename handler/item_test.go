package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/tinfoilsh/tinfoil-buckets/auth"
	"github.com/tinfoilsh/tinfoil-buckets/store"
)

const testAPIKey = "tk_test_key_used_in_unit_tests_only"

type mockS3 struct {
	objects map[string][]byte
}

func newMockS3() *mockS3 {
	return &mockS3{objects: make(map[string][]byte)}
}

func (m *mockS3) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	data, _ := io.ReadAll(input.Body)
	m.objects[*input.Key] = data
	return &s3.PutObjectOutput{}, nil
}

func (m *mockS3) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	data, ok := m.objects[*input.Key]
	if !ok {
		return nil, &types.NoSuchKey{}
	}
	return &s3.GetObjectOutput{
		Body: io.NopCloser(bytes.NewReader(data)),
	}, nil
}

func (m *mockS3) DeleteObject(_ context.Context, input *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	delete(m.objects, *input.Key)
	return &s3.DeleteObjectOutput{}, nil
}

func (m *mockS3) HeadObject(_ context.Context, input *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if _, ok := m.objects[*input.Key]; !ok {
		return nil, &types.NoSuchKey{}
	}
	return &s3.HeadObjectOutput{}, nil
}

// stubResolver returns a fixed identity for any token. err, when set,
// short-circuits Resolve before consulting identity.
type stubResolver struct {
	identity auth.Identity
	err      error
}

func (s *stubResolver) Resolve(_ context.Context, _ string) (auth.Identity, error) {
	if s.err != nil {
		return auth.Identity{}, s.err
	}
	return s.identity, nil
}

func randomKeyB64(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	rand.Read(key)
	return base64.StdEncoding.EncodeToString(key)
}

// randomAccessToken returns a 36-char hex string suitable for use as an
// accessToken (satisfies minAccessTokenLength=36 and contains no
// URL-special chars). The accessToken is the URL handle, not auth.
func randomAccessToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 18)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// authReq builds an httptest request with the Bearer token already set,
// matching how the bucket's clients are expected to call the API.
func authReq(method, target string, body []byte) *http.Request {
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, bytes.NewReader(body))
	}
	r.Header.Set("Authorization", "Bearer "+testAPIKey)
	return r
}

func setupHandler() (*ItemHandler, *mockS3) {
	m := newMockS3()
	s := store.NewR2StoreWithClient(m, "test")
	return NewItemHandler(s, &stubResolver{identity: auth.Identity{UserID: "user_test"}}), m
}

func setupHandlerWithResolver(resolver auth.Resolver) *ItemHandler {
	s := store.NewR2StoreWithClient(newMockS3(), "test")
	return NewItemHandler(s, resolver)
}

func TestPutAndGet(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("hello world"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var putResp PutResponse
	json.NewDecoder(rec.Body).Decode(&putResp)
	if putResp.Version != 1 {
		t.Fatalf("version: got %d, want 1", putResp.Version)
	}

	req = authReq(http.MethodGet, "/items/"+tok, nil)
	req.Header.Set("X-Encryption-Key", key)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var getResp GetResponse
	json.NewDecoder(rec.Body).Decode(&getResp)
	if getResp.Value != value {
		t.Fatalf("value: got %q, want %q", getResp.Value, value)
	}
}

func TestGetNotFound(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)

	req := authReq(http.MethodGet, "/items/"+randomAccessToken(t), nil)
	req.Header.Set("X-Encryption-Key", key)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestGetWrongKey(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	wrongKey := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("secret"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	req = authReq(http.MethodGet, "/items/"+tok, nil)
	req.Header.Set("X-Encryption-Key", wrongKey)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestVersionIncrement(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	tok := randomAccessToken(t)

	for i := 1; i <= 3; i++ {
		value := base64.StdEncoding.EncodeToString([]byte("v" + string(rune('0'+i))))
		body, _ := json.Marshal(PutRequest{
			Value:          value,
			EncryptionKeys: []string{key},
		})
		req := authReq(http.MethodPut, "/items/"+tok, body)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		var resp PutResponse
		json.NewDecoder(rec.Body).Decode(&resp)
		if resp.Version != uint64(i) {
			t.Fatalf("iteration %d: got version %d, want %d", i, resp.Version, i)
		}
	}
}

func TestHead(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	req = authReq(http.MethodHead, "/items/"+tok, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD: got %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Header().Get("X-Version") != "1" {
		t.Fatalf("X-Version: got %q, want %q", rec.Header().Get("X-Version"), "1")
	}
	if rec.Header().Get("X-Num-Encryption-Keys") != "1" {
		t.Fatalf("X-Num-Encryption-Keys: got %q, want %q", rec.Header().Get("X-Num-Encryption-Keys"), "1")
	}
}

func TestDelete(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	req = authReq(http.MethodDelete, "/items/"+tok, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE: got %d, want %d", rec.Code, http.StatusNoContent)
	}

	req = authReq(http.MethodGet, "/items/"+tok, nil)
	req.Header.Set("X-Encryption-Key", key)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET after DELETE: got %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestAddAndRemoveKey(t *testing.T) {
	h, _ := setupHandler()
	key1 := randomKeyB64(t)
	key2 := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("shared secret"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key1},
	})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body, _ = json.Marshal(AddKeyRequest{ExistingEncryptionKey: key1, NewEncryptionKey: key2})
	req = authReq(http.MethodPost, "/items/"+tok+"/encryption-keys", body)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("AddKey: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	req = authReq(http.MethodGet, "/items/"+tok, nil)
	req.Header.Set("X-Encryption-Key", key2)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET with key2: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	body, _ = json.Marshal(RemoveKeyRequest{ExistingEncryptionKey: key2, RemoveEncryptionKey: key1})
	req = authReq(http.MethodDelete, "/items/"+tok+"/encryption-keys", body)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("RemoveKey: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	req = authReq(http.MethodGet, "/items/"+tok, nil)
	req.Header.Set("X-Encryption-Key", key1)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET with removed key: got %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestV0PutAndGet(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("v0 data"))
	format := 0

	body, _ := json.Marshal(PutRequest{
		Value:         value,
		EncryptionKey: key,
		Format:        &format,
	})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT v0: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	req = authReq(http.MethodGet, "/items/"+tok, nil)
	req.Header.Set("X-Encryption-Key", key)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET v0: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var getResp GetResponse
	json.NewDecoder(rec.Body).Decode(&getResp)
	if getResp.Value != value {
		t.Fatalf("value: got %q, want %q", getResp.Value, value)
	}
	if getResp.Format != 0 {
		t.Fatalf("format: got %d, want 0", getResp.Format)
	}
}

func TestV0WrongKey(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	wrongKey := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("secret"))
	format := 0

	body, _ := json.Marshal(PutRequest{
		Value:         value,
		EncryptionKey: key,
		Format:        &format,
	})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	req = authReq(http.MethodGet, "/items/"+tok, nil)
	req.Header.Set("X-Encryption-Key", wrongKey)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestV0AddKeyRejected(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	newKey := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))
	format := 0

	body, _ := json.Marshal(PutRequest{
		Value:         value,
		EncryptionKey: key,
		Format:        &format,
	})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body, _ = json.Marshal(AddKeyRequest{ExistingEncryptionKey: key, NewEncryptionKey: newKey})
	req = authReq(http.MethodPost, "/items/"+tok+"/encryption-keys", body)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("AddKey on v0: got %d, want %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestV0HeadFormat(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))
	format := 0

	body, _ := json.Marshal(PutRequest{
		Value:         value,
		EncryptionKey: key,
		Format:        &format,
	})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	req = authReq(http.MethodHead, "/items/"+tok, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD v0: got %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Header().Get("X-Format") != "0" {
		t.Fatalf("X-Format: got %q, want %q", rec.Header().Get("X-Format"), "0")
	}
	if rec.Header().Get("X-Version") != "" {
		t.Fatalf("X-Version should be empty for v0, got %q", rec.Header().Get("X-Version"))
	}
}

func TestPutWithoutAccessTokenRejected(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	req := authReq(http.MethodPut, "/items/", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT without access_token: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestPutWithShortAccessTokenRejected(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	// 35 chars — one short of the 36-char minimum
	req := authReq(http.MethodPut, "/items/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with short access_token: got %d, want %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestPutWithLongAccessTokenRejected(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	// 77 chars — one over the 76-char maximum
	req := authReq(http.MethodPut, "/items/"+strings.Repeat("a", 77), body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with long access_token: got %d, want %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestPutWithInvalidAccessTokenCharsRejected(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	// Each token is within the length bounds but contains a character
	// outside the allowed charset. The router strips /items/ and any
	// /encryption-keys suffix; everything else hits validateAccessToken,
	// which must reject these so they can't end up as R2 key fragments.
	cases := map[string]string{
		"slash": strings.Repeat("a", 20) + "/" + strings.Repeat("b", 19),
		"tilde": strings.Repeat("a", 20) + "~" + strings.Repeat("b", 19),
		"comma": strings.Repeat("a", 20) + "," + strings.Repeat("b", 19),
		"plus":  strings.Repeat("a", 20) + "+" + strings.Repeat("b", 19),
		"dot":   strings.Repeat("a", 20) + "." + strings.Repeat("b", 19),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			body, _ := json.Marshal(PutRequest{Value: value, EncryptionKeys: []string{key}})
			req := authReq(http.MethodPut, "/items/"+tok, body)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		})
	}
}

func TestPutResponseHasNoAccessToken(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// The PUT response must not echo the accessToken back. Decode into a
	// generic map so we can assert by-key without coupling to the struct.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}
	if _, ok := raw["access_token"]; ok {
		t.Fatalf("expected no access_token field in PUT response, got: %v", raw)
	}
}

func TestHeadReturnsFingerprints(t *testing.T) {
	h, _ := setupHandler()
	key1 := randomKeyB64(t)
	key2 := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key1, key2},
	})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	req = authReq(http.MethodHead, "/items/"+tok, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD: got %d, want %d", rec.Code, http.StatusOK)
	}

	fps := rec.Header().Get("X-Encryption-Key-Fingerprints")
	if fps == "" {
		t.Fatal("expected X-Encryption-Key-Fingerprints header")
	}
	parts := strings.Split(fps, ",")
	if len(parts) != 2 {
		t.Fatalf("expected 2 fingerprints, got %d: %q", len(parts), fps)
	}
	for i, fp := range parts {
		if len(fp) != 64 {
			t.Fatalf("fingerprint %d: expected 64 hex chars, got %d: %q", i, len(fp), fp)
		}
	}
}

func TestStorageKeyOrgPrefix(t *testing.T) {
	m := newMockS3()
	s := store.NewR2StoreWithClient(m, "test")
	h := NewItemHandler(s, &stubResolver{identity: auth.Identity{UserID: "user_x", OrgID: "org_y"}})

	key := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{Value: value, EncryptionKeys: []string{key}})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	want := "org/org_y/" + tok
	if _, ok := m.objects[want]; !ok {
		t.Fatalf("expected R2 key %q, got keys: %v", want, mapKeys(m.objects))
	}
}

func TestStorageKeyUserPrefix(t *testing.T) {
	m := newMockS3()
	s := store.NewR2StoreWithClient(m, "test")
	h := NewItemHandler(s, &stubResolver{identity: auth.Identity{UserID: "user_x"}})

	key := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{Value: value, EncryptionKeys: []string{key}})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	want := "user/user_x/" + tok
	if _, ok := m.objects[want]; !ok {
		t.Fatalf("expected R2 key %q, got keys: %v", want, mapKeys(m.objects))
	}
}

func TestStorageKeyWithSegments(t *testing.T) {
	m := newMockS3()
	s := store.NewR2StoreWithClient(m, "test")
	h := NewItemHandler(s, &stubResolver{identity: auth.Identity{UserID: "user_x", OrgID: "org_y"}})

	key := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{Value: value, EncryptionKeys: []string{key}})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	req.Header.Set("X-Item-Path", "customers/abc/profile")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	want := "org/org_y/customers/abc/profile/" + tok
	if _, ok := m.objects[want]; !ok {
		t.Fatalf("expected R2 key %q, got keys: %v", want, mapKeys(m.objects))
	}
}

func TestSegmentsIsolateNamespaces(t *testing.T) {
	// Same accessToken, same encryption key, two different X-Item-Path
	// values must produce two distinct items.
	m := newMockS3()
	s := store.NewR2StoreWithClient(m, "test")
	h := NewItemHandler(s, &stubResolver{identity: auth.Identity{UserID: "user_x"}})

	encKey := randomKeyB64(t)
	tok := randomAccessToken(t)

	for i, segs := range []string{"a", "b"} {
		value := base64.StdEncoding.EncodeToString([]byte{byte('A' + i)})
		body, _ := json.Marshal(PutRequest{Value: value, EncryptionKeys: []string{encKey}})
		req := authReq(http.MethodPut, "/items/"+tok, body)
		req.Header.Set("X-Item-Path", segs)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT %s: got %d", segs, rec.Code)
		}
	}

	if _, ok := m.objects["user/user_x/a/"+tok]; !ok {
		t.Fatalf("expected key user/user_x/a/<tok>, got %v", mapKeys(m.objects))
	}
	if _, ok := m.objects["user/user_x/b/"+tok]; !ok {
		t.Fatalf("expected key user/user_x/b/<tok>, got %v", mapKeys(m.objects))
	}
}

func TestRejectTooManySegments(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{Value: value, EncryptionKeys: []string{key}})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	req.Header.Set("X-Item-Path", "a/b/c/d/e") // 5 segments
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestRejectSegmentTooLong(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{Value: value, EncryptionKeys: []string{key}})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	req.Header.Set("X-Item-Path", strings.Repeat("a", 37))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestRejectInvalidSegmentChars(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{Value: value, EncryptionKeys: []string{key}})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	req.Header.Set("X-Item-Path", "abc def") // space disallowed
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestUUIDLikeSegmentAccepted(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{Value: value, EncryptionKeys: []string{key}})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	req.Header.Set("X-Item-Path", "550e8400-e29b-41d4-a716-446655440000") // 36-char uuid
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestMissingAuthorizationReturns401(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{Value: value, EncryptionKeys: []string{key}})
	// Note: no Authorization header — using plain httptest.NewRequest.
	req := httptest.NewRequest(http.MethodPut, "/items/"+tok, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestEmptyBearerReturns401(t *testing.T) {
	h, _ := setupHandler()
	key := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{Value: value, EncryptionKeys: []string{key}})
	req := httptest.NewRequest(http.MethodPut, "/items/"+tok, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestInvalidTokenReturns401(t *testing.T) {
	h := setupHandlerWithResolver(&stubResolver{err: auth.ErrInvalidToken})
	key := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{Value: value, EncryptionKeys: []string{key}})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestUpstreamUnavailableReturns502(t *testing.T) {
	h := setupHandlerWithResolver(&stubResolver{err: auth.ErrUpstreamUnavailable})
	key := randomKeyB64(t)
	tok := randomAccessToken(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{Value: value, EncryptionKeys: []string{key}})
	req := authReq(http.MethodPut, "/items/"+tok, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

func mapKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
