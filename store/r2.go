package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3API is the subset of the S3 client used by the store.
type S3API interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

// R2Store wraps an S3-compatible client for Cloudflare R2.
type R2Store struct {
	client S3API
	bucket string
}

// NewR2Store creates an R2Store using Cloudflare account credentials.
func NewR2Store(accountID, accessKeyID, secretAccessKey, bucket string) *R2Store {
	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID)),
		Region:       "auto",
		Credentials:  credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, ""),
	})
	return &R2Store{client: client, bucket: bucket}
}

// NewR2StoreWithClient creates an R2Store with a custom S3 client (for testing).
func NewR2StoreWithClient(client S3API, bucket string) *R2Store {
	return &R2Store{client: client, bucket: bucket}
}

// Put stores raw bytes at the given lookup key.
func (s *R2Store) Put(ctx context.Context, lookupKey string, data []byte) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &s.bucket,
		Key:         &lookupKey,
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/octet-stream"),
	})
	if err != nil {
		return fmt.Errorf("r2 put %q: %w", lookupKey, err)
	}
	return nil
}

// Get retrieves raw bytes for the given lookup key. Returns nil, nil if not found.
func (s *R2Store) Get(ctx context.Context, lookupKey string) ([]byte, error) {
	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &s.bucket,
		Key:    &lookupKey,
	})
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("r2 get %q: %w", lookupKey, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("r2 read %q: %w", lookupKey, err)
	}
	return data, nil
}

// Delete removes the object at the given lookup key.
func (s *R2Store) Delete(ctx context.Context, lookupKey string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &s.bucket,
		Key:    &lookupKey,
	})
	if err != nil {
		return fmt.Errorf("r2 delete %q: %w", lookupKey, err)
	}
	return nil
}

// Exists checks whether an object exists at the given lookup key.
func (s *R2Store) Exists(ctx context.Context, lookupKey string) (bool, error) {
	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &s.bucket,
		Key:    &lookupKey,
	})
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("r2 head %q: %w", lookupKey, err)
	}
	return true, nil
}

// ListKeys returns lookup keys matching the given prefix.
func (s *R2Store) ListKeys(ctx context.Context, prefix string, maxKeys int32) ([]string, error) {
	input := &s3.ListObjectsV2Input{
		Bucket:  &s.bucket,
		MaxKeys: &maxKeys,
	}
	if prefix != "" {
		input.Prefix = &prefix
	}

	var lookupKeys []string
	for {
		resp, err := s.client.ListObjectsV2(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("r2 list prefix=%q: %w", prefix, err)
		}

		for _, obj := range resp.Contents {
			if obj.Key != nil {
				lookupKeys = append(lookupKeys, *obj.Key)
			}
		}

		if resp.IsTruncated == nil || !*resp.IsTruncated {
			break
		}
		input.ContinuationToken = resp.NextContinuationToken
	}

	return lookupKeys, nil
}

func isNotFound(err error) bool {
	var nsk *types.NoSuchKey
	if ok := errors.As(err, &nsk); ok {
		return true
	}
	// HeadObject returns a generic error with "NotFound" or 404
	return strings.Contains(err.Error(), "NotFound") || strings.Contains(err.Error(), "404")
}
