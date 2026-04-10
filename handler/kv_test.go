package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/tinfoilsh/confidential-kv/store"
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

func (m *mockS3) ListObjectsV2(_ context.Context, input *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	var contents []types.Object
	for k := range m.objects {
		if input.Prefix == nil || (len(k) >= len(*input.Prefix) && k[:len(*input.Prefix)] == *input.Prefix) {
			key := k
			contents = append(contents, types.Object{Key: &key})
		}
	}
	return &s3.ListObjectsV2Output{
		Contents:    contents,
		IsTruncated: aws.Bool(false),
	}, nil
}

func randomKeyB64(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	rand.Read(key)
	return base64.StdEncoding.EncodeToString(key)
}

func setupHandler() *KVHandler {
	s := store.NewR2StoreWithClient(newMockS3(), "test")
	return NewKVHandler(s)
}

func TestPutAndGet(t *testing.T) {
	h := setupHandler()
	key := randomKeyB64(t)
	value := base64.StdEncoding.EncodeToString([]byte("hello world"))

	// PUT
	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	req := httptest.NewRequest(http.MethodPut, "/kv/test-key", bytes.NewReader(body))
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
	req = httptest.NewRequest(http.MethodGet, "/kv/test-key", nil)
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

	req := httptest.NewRequest(http.MethodGet, "/kv/nonexistent", nil)
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
	value := base64.StdEncoding.EncodeToString([]byte("secret"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	req := httptest.NewRequest(http.MethodPut, "/kv/test-key", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	req = httptest.NewRequest(http.MethodGet, "/kv/test-key", nil)
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

	for i := 1; i <= 3; i++ {
		value := base64.StdEncoding.EncodeToString([]byte("v" + string(rune('0'+i))))
		body, _ := json.Marshal(PutRequest{
			Value:          value,
			EncryptionKeys: []string{key},
		})
		req := httptest.NewRequest(http.MethodPut, "/kv/versioned", bytes.NewReader(body))
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
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	req := httptest.NewRequest(http.MethodPut, "/kv/head-test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	req = httptest.NewRequest(http.MethodHead, "/kv/head-test", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD: got %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Header().Get("X-Version") != "1" {
		t.Fatalf("X-Version: got %q, want %q", rec.Header().Get("X-Version"), "1")
	}
	if rec.Header().Get("X-Num-Keys") != "1" {
		t.Fatalf("X-Num-Keys: got %q, want %q", rec.Header().Get("X-Num-Keys"), "1")
	}
}

func TestDelete(t *testing.T) {
	h := setupHandler()
	key := randomKeyB64(t)
	value := base64.StdEncoding.EncodeToString([]byte("data"))

	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key},
	})
	req := httptest.NewRequest(http.MethodPut, "/kv/del-test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	req = httptest.NewRequest(http.MethodDelete, "/kv/del-test", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE: got %d, want %d", rec.Code, http.StatusNoContent)
	}

	req = httptest.NewRequest(http.MethodGet, "/kv/del-test", nil)
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
	value := base64.StdEncoding.EncodeToString([]byte("shared secret"))

	// PUT with key1
	body, _ := json.Marshal(PutRequest{
		Value:          value,
		EncryptionKeys: []string{key1},
	})
	req := httptest.NewRequest(http.MethodPut, "/kv/shared", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// Add key2
	body, _ = json.Marshal(AddKeyRequest{ExistingKey: key1, NewKey: key2})
	req = httptest.NewRequest(http.MethodPost, "/kv/shared/keys", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("AddKey: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// GET with key2
	req = httptest.NewRequest(http.MethodGet, "/kv/shared", nil)
	req.Header.Set("X-Encryption-Key", key2)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET with key2: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// Remove key1
	body, _ = json.Marshal(RemoveKeyRequest{ExistingKey: key2, RemoveKey: key1})
	req = httptest.NewRequest(http.MethodDelete, "/kv/shared/keys", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("RemoveKey: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// key1 should no longer work
	req = httptest.NewRequest(http.MethodGet, "/kv/shared", nil)
	req.Header.Set("X-Encryption-Key", key1)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET with removed key: got %d, want %d", rec.Code, http.StatusForbidden)
	}
}
