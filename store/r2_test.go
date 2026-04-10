package store

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
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
		if input.Prefix == nil || len(*input.Prefix) == 0 || len(k) >= len(*input.Prefix) && k[:len(*input.Prefix)] == *input.Prefix {
			key := k
			contents = append(contents, types.Object{Key: &key})
		}
	}
	return &s3.ListObjectsV2Output{
		Contents:    contents,
		IsTruncated: aws.Bool(false),
	}, nil
}

func TestPutGetDelete(t *testing.T) {
	s := NewR2StoreWithClient(newMockS3(), "test-bucket")
	ctx := context.Background()

	if err := s.Put(ctx, "key1", []byte("value1")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	data, err := s.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(data, []byte("value1")) {
		t.Fatalf("got %q, want %q", data, "value1")
	}

	if err := s.Delete(ctx, "key1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	data, err = s.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Get after delete: %v", err)
	}
	if data != nil {
		t.Fatalf("expected nil, got %q", data)
	}
}

func TestGetNotFound(t *testing.T) {
	s := NewR2StoreWithClient(newMockS3(), "test-bucket")
	data, err := s.Get(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if data != nil {
		t.Fatalf("expected nil, got %q", data)
	}
}

func TestExists(t *testing.T) {
	s := NewR2StoreWithClient(newMockS3(), "test-bucket")
	ctx := context.Background()

	exists, err := s.Exists(ctx, "key1")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Fatal("expected false")
	}

	s.Put(ctx, "key1", []byte("data"))

	exists, err = s.Exists(ctx, "key1")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Fatal("expected true")
	}
}

func TestListKeys(t *testing.T) {
	s := NewR2StoreWithClient(newMockS3(), "test-bucket")
	ctx := context.Background()

	s.Put(ctx, "prefix/a", []byte("1"))
	s.Put(ctx, "prefix/b", []byte("2"))
	s.Put(ctx, "other/c", []byte("3"))

	keys, err := s.ListKeys(ctx, "prefix/", 100)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
}
