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

	"github.com/tinfoilsh/tinfoil-buckets/store"
)

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

func randomKeyB64(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	rand.Read(key)
	return base64.StdEncoding.EncodeToString(key)
}

// randomLookupKey returns a 36-char hex string suitable for use as a lookup_key
// (satisfies minLookupKeyLength=36 and contains no URL-special chars).
func randomLookupKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 18)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func setupHandler() *BucketHandler {
	s := store.NewR2StoreWithClient(newMockS3(), "test")
	return NewBucketHandler(s)
}

func TestPutAndGet(t *testing.T) {
	h := setupHandler()
	key := randomKeyB64(t)
	lk := randomLookupKey(t)
	value := base64.StdEncoding.EncodeToString([]byte("hello world"))

	// PUT
	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	req := httptest.NewRequest(http.MethodPut, "/buckets/"+lk, bytes.NewReader(body))
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

	// GET
	req = httptest.NewRequest(http.MethodGet, "/buckets/"+lk, nil)
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
	h := setupHandler()
	key := randomKeyB64(t)

	req := httptest.NewRequest(http.MethodGet, "/buckets/"+randomLookupKey(t), nil)
	req.Header.Set("X-Encryption-Key", key)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestGetWrongKey(t *testing.T) {
	h := setupHandler()
	key := randomKeyB64(t)
	wrongKey := randomKeyB64(t)
	lk := randomLookupKey(t)
	value := base64.StdEncoding.EncodeToString([]byte("secret"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	req := httptest.NewRequest(http.MethodPut, "/buckets/"+lk, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	req = httptest.NewRequest(http.MethodGet, "/buckets/"+lk, nil)
	req.Header.Set("X-Encryption-Key", wrongKey)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestVersionIncrement(t *testing.T) {
	h := setupHandler()
	key := randomKeyB64(t)
	lk := randomLookupKey(t)

	for i := 1; i <= 3; i++ {
		value := base64.StdEncoding.EncodeToString([]byte("v" + string(rune('0'+i))))
		body, _ := json.Marshal(PutRequest{
			Value:          value,
			EncryptionKeys: []string{key},
		})
		req := httptest.NewRequest(http.MethodPut, "/buckets/"+lk, bytes.NewReader(body))
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
	h := setupHandler()
	key := randomKeyB64(t)
	lk := randomLookupKey(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	req := httptest.NewRequest(http.MethodPut, "/buckets/"+lk, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	req = httptest.NewRequest(http.MethodHead, "/buckets/"+lk, nil)
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
	h := setupHandler()
	key := randomKeyB64(t)
	lk := randomLookupKey(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	req := httptest.NewRequest(http.MethodPut, "/buckets/"+lk, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	req = httptest.NewRequest(http.MethodDelete, "/buckets/"+lk, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE: got %d, want %d", rec.Code, http.StatusNoContent)
	}

	req = httptest.NewRequest(http.MethodGet, "/buckets/"+lk, nil)
	req.Header.Set("X-Encryption-Key", key)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET after DELETE: got %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestAddAndRemoveKey(t *testing.T) {
	h := setupHandler()
	key1 := randomKeyB64(t)
	key2 := randomKeyB64(t)
	lk := randomLookupKey(t)
	value := base64.StdEncoding.EncodeToString([]byte("shared secret"))

	// PUT with key1
	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key1},
	})
	req := httptest.NewRequest(http.MethodPut, "/buckets/"+lk, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// Add key2
	body, _ = json.Marshal(AddKeyRequest{ExistingEncryptionKey: key1, NewEncryptionKey: key2})
	req = httptest.NewRequest(http.MethodPost, "/buckets/"+lk+"/encryption-keys", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("AddKey: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// GET with key2
	req = httptest.NewRequest(http.MethodGet, "/buckets/"+lk, nil)
	req.Header.Set("X-Encryption-Key", key2)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET with key2: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// Remove key1
	body, _ = json.Marshal(RemoveKeyRequest{ExistingEncryptionKey: key2, RemoveEncryptionKey: key1})
	req = httptest.NewRequest(http.MethodDelete, "/buckets/"+lk+"/encryption-keys", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("RemoveKey: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// key1 should no longer work
	req = httptest.NewRequest(http.MethodGet, "/buckets/"+lk, nil)
	req.Header.Set("X-Encryption-Key", key1)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET with removed key: got %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestV0PutAndGet(t *testing.T) {
	h := setupHandler()
	key := randomKeyB64(t)
	lk := randomLookupKey(t)
	value := base64.StdEncoding.EncodeToString([]byte("v0 data"))
	format := 0

	body, _ := json.Marshal(PutRequest{
		Value:         value,
		EncryptionKey: key,
		Format:        &format,
	})
	req := httptest.NewRequest(http.MethodPut, "/buckets/"+lk, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT v0: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// GET with same key
	req = httptest.NewRequest(http.MethodGet, "/buckets/"+lk, nil)
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
	h := setupHandler()
	key := randomKeyB64(t)
	wrongKey := randomKeyB64(t)
	lk := randomLookupKey(t)
	value := base64.StdEncoding.EncodeToString([]byte("secret"))
	format := 0

	body, _ := json.Marshal(PutRequest{
		Value:         value,
		EncryptionKey: key,
		Format:        &format,
	})
	req := httptest.NewRequest(http.MethodPut, "/buckets/"+lk, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	req = httptest.NewRequest(http.MethodGet, "/buckets/"+lk, nil)
	req.Header.Set("X-Encryption-Key", wrongKey)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestV0AddKeyRejected(t *testing.T) {
	h := setupHandler()
	key := randomKeyB64(t)
	newKey := randomKeyB64(t)
	lk := randomLookupKey(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))
	format := 0

	body, _ := json.Marshal(PutRequest{
		Value:         value,
		EncryptionKey: key,
		Format:        &format,
	})
	req := httptest.NewRequest(http.MethodPut, "/buckets/"+lk, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body, _ = json.Marshal(AddKeyRequest{ExistingEncryptionKey: key, NewEncryptionKey: newKey})
	req = httptest.NewRequest(http.MethodPost, "/buckets/"+lk+"/encryption-keys", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("AddKey on v0: got %d, want %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestV0HeadFormat(t *testing.T) {
	h := setupHandler()
	key := randomKeyB64(t)
	lk := randomLookupKey(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))
	format := 0

	body, _ := json.Marshal(PutRequest{
		Value:         value,
		EncryptionKey: key,
		Format:        &format,
	})
	req := httptest.NewRequest(http.MethodPut, "/buckets/"+lk, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	req = httptest.NewRequest(http.MethodHead, "/buckets/"+lk, nil)
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

func TestPutWithoutLookupKeyRejected(t *testing.T) {
	h := setupHandler()
	key := randomKeyB64(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	req := httptest.NewRequest(http.MethodPut, "/buckets/", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT without lookup_key: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestPutWithShortLookupKeyRejected(t *testing.T) {
	h := setupHandler()
	key := randomKeyB64(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	// 35 chars — one short of the 36-char minimum
	req := httptest.NewRequest(http.MethodPut, "/buckets/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with short lookup_key: got %d, want %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestPutReturnsKeyInResponse(t *testing.T) {
	h := setupHandler()
	key := randomKeyB64(t)
	lk := randomLookupKey(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	req := httptest.NewRequest(http.MethodPut, "/buckets/"+lk, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var putResp PutResponse
	json.NewDecoder(rec.Body).Decode(&putResp)
	if putResp.LookupKey != lk {
		t.Fatalf("lookup_key: got %q, want %q", putResp.LookupKey, lk)
	}
}

func TestHeadReturnsFingerprints(t *testing.T) {
	h := setupHandler()
	key1 := randomKeyB64(t)
	key2 := randomKeyB64(t)
	lk := randomLookupKey(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key1, key2},
	})
	req := httptest.NewRequest(http.MethodPut, "/buckets/"+lk, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	req = httptest.NewRequest(http.MethodHead, "/buckets/"+lk, nil)
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
	// Each fingerprint is hex-encoded SHA-256 = 64 chars
	for i, fp := range parts {
		if len(fp) != 64 {
			t.Fatalf("fingerprint %d: expected 64 hex chars, got %d: %q", i, len(fp), fp)
		}
	}
}
