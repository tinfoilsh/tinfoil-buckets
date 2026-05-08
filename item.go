package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/tinfoilsh/usage-reporting-go/contract"
)

// UsageReporter records one usage event per successful storage operation.
// The handler tolerates a nil reporter so local dev without a controlplane
// keeps working.
type UsageReporter interface {
	ReportOperation(req *http.Request, identity Identity, operationName string, attributes map[string]string)
}

type ItemHandler struct {
	store    *R2Store
	resolver Resolver
	reporter UsageReporter
}

func NewItemHandler(store *R2Store, resolver Resolver, reporter UsageReporter) *ItemHandler {
	return &ItemHandler{store: store, resolver: resolver, reporter: reporter}
}

func (h *ItemHandler) report(r *http.Request, identity Identity, operationName string, attrs map[string]string) {
	if h.reporter == nil {
		return
	}
	h.reporter.ReportOperation(r, identity, operationName, attrs)
}

// PUT /items/{accessToken}
type PutRequest struct {
	Value          string   `json:"value"`                     // base64-encoded
	EncryptionKeys []string `json:"encryption_keys,omitempty"` // base64-encoded 32-byte keys (required for v1)
	EncryptionKey  string   `json:"encryption_key,omitempty"`  // single base64 key (required for v0)
	Format         *int     `json:"format,omitempty"`          // 0 or 1 (default: 1)
}

// PutResponse confirms a successful write. For v1 it also surfaces the
// stored version and original creation timestamp; v0 has no metadata, so
// the body is empty (status 200 alone is the confirmation).
type PutResponse struct {
	Version   uint64 `json:"version,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// POST /items/{accessToken}/encryption-keys
type AddKeyRequest struct {
	ExistingEncryptionKey string `json:"existing_encryption_key"` // base64
	NewEncryptionKey      string `json:"new_encryption_key"`      // base64
}

// DELETE /items/{accessToken}/encryption-keys
type RemoveKeyRequest struct {
	ExistingEncryptionKey string `json:"existing_encryption_key"` // base64
	RemoveEncryptionKey   string `json:"remove_encryption_key"`   // base64
}

// GET /items/{accessToken} response
type GetResponse struct {
	Value     string `json:"value"`                // base64-encoded
	Version   uint64 `json:"version,omitempty"`    // v1 only
	CreatedAt string `json:"created_at,omitempty"` // v1 only
	Format    uint8  `json:"format"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

const (
	minAccessTokenLength = 36
	maxAccessTokenLength = 76
	maxPathSegments      = 4
	maxPathSegmentLength = 36
	routePrefix          = "/items/"
	pathHeader           = "X-Item-Path"
)

const (
	operationPutObject    = contract.OperationBucketsPutObject
	operationGetObject    = contract.OperationBucketsGetObject
	operationHeadObject   = contract.OperationBucketsHeadObject
	operationDeleteObject = contract.OperationBucketsDeleteObject
	operationAddKey       = contract.OperationBucketsAddKey
	operationRemoveKey    = contract.OperationBucketsRemoveKey
)

func validateAccessToken(accessToken string) error {
	if accessToken == "" {
		return fmt.Errorf("access_token is required")
	}
	if n := len(accessToken); n < minAccessTokenLength || n > maxAccessTokenLength {
		return fmt.Errorf("access_token must be between %d and %d characters", minAccessTokenLength, maxAccessTokenLength)
	}
	if !isValidSegment(accessToken) {
		return fmt.Errorf("access_token contains invalid characters (allowed: A-Z, a-z, 0-9, '_', '-')")
	}
	return nil
}

// validatePathSegments parses the X-Item-Path header. Empty header returns
// nil, nil (caller is operating at the tenant root). Otherwise: up to
// maxPathSegments slash-separated segments, each 1..maxPathSegmentLength
// chars, charset [A-Za-z0-9_-].
func validatePathSegments(header string) ([]string, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil, nil
	}
	segments := strings.Split(header, "/")
	if len(segments) > maxPathSegments {
		return nil, fmt.Errorf("X-Item-Path may contain at most %d segments", maxPathSegments)
	}
	for i, seg := range segments {
		if seg == "" {
			return nil, fmt.Errorf("X-Item-Path segment %d is empty", i)
		}
		if len(seg) > maxPathSegmentLength {
			return nil, fmt.Errorf("X-Item-Path segment %d exceeds %d characters", i, maxPathSegmentLength)
		}
		if !isValidSegment(seg) {
			return nil, fmt.Errorf("X-Item-Path segment %d contains invalid characters (allowed: A-Z, a-z, 0-9, '_', '-')", i)
		}
	}
	return segments, nil
}

// [A-Za-z0-9_-]
func isValidSegment(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// storageKey builds the R2 object key from an identity, caller-supplied
// path segments, and the accessToken (URL handle). Org-scoped keys win
// when an org is present; otherwise the owning user namespace is used.
// The two namespaces are disjoint. The accessToken is the leaf of the
// key — it lives under the tenant + segment prefix so that callers can
// have many distinct items addressed by their own identifier.
func storageKey(id Identity, segments []string, accessToken string) string {
	var prefix string
	if id.OrgID != "" {
		prefix = "org/" + id.OrgID
	} else {
		prefix = "user/" + id.UserID
	}
	parts := make([]string, 0, 2+len(segments))
	parts = append(parts, prefix)
	parts = append(parts, segments...)
	parts = append(parts, accessToken)
	return strings.Join(parts, "/")
}

// bearerToken extracts the API key from an Authorization header. Returns
// an error if the header is missing or malformed.
func bearerToken(h string) (string, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", fmt.Errorf("missing or invalid Authorization header")
	}
	tok := strings.TrimSpace(h[len(prefix):])
	if tok == "" {
		return "", fmt.Errorf("Authorization header has empty bearer token")
	}
	return tok, nil
}

// resolve performs the per-request identity lookup, segment parsing, and
// storage-key construction. The API key is read from the Authorization
// header and forwarded to controlplane; the accessToken from the URL is
// only used as the leaf of the storage key. Returns the namespaced R2
// storage key, the resolved identity for usage attribution, or false
// after writing an HTTP error.
func (h *ItemHandler) resolve(w http.ResponseWriter, r *http.Request, accessToken string) (string, Identity, bool) {
	apiKey, err := bearerToken(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return "", Identity{}, false
	}

	segments, err := validatePathSegments(r.Header.Get(pathHeader))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return "", Identity{}, false
	}

	id, err := h.resolver.Resolve(r.Context(), apiKey)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidToken):
			writeError(w, http.StatusUnauthorized, "invalid api key")
		case errors.Is(err, ErrUpstreamUnavailable):
			log.Errorf("identity service unavailable: %v", err)
			writeError(w, http.StatusBadGateway, "identity service unavailable")
		default:
			log.Errorf("identity resolve failed: %v", err)
			writeError(w, http.StatusInternalServerError, "identity resolve failed")
		}
		return "", Identity{}, false
	}
	return storageKey(id, segments, accessToken), id, true
}

func (h *ItemHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if !strings.HasPrefix(path, routePrefix) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	rest := path[len(routePrefix):]

	if accessToken, ok := strings.CutSuffix(rest, "/encryption-keys"); ok {
		if err := validateAccessToken(accessToken); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		key, identity, ok := h.resolve(w, r, accessToken)
		if !ok {
			return
		}
		switch r.Method {
		case http.MethodPost:
			h.handleAddKey(w, r, identity, key)
		case http.MethodDelete:
			h.handleRemoveKey(w, r, identity, key)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}

	accessToken := rest

	if err := validateAccessToken(accessToken); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	key, identity, ok := h.resolve(w, r, accessToken)
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodPut:
		h.handlePut(w, r, identity, key)
	case http.MethodGet:
		h.handleGet(w, r, identity, key)
	case http.MethodHead:
		h.handleHead(w, r, identity, key)
	case http.MethodDelete:
		h.handleDelete(w, r, identity, key)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *ItemHandler) handlePut(w http.ResponseWriter, r *http.Request, identity Identity, key string) {
	var req PutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	value, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 value")
		return
	}

	format := uint8(FormatV1)
	if req.Format != nil {
		format = uint8(*req.Format)
	}

	var resp PutResponse
	var blob []byte

	switch format {
	case FormatV0:
		if req.EncryptionKey == "" {
			writeError(w, http.StatusBadRequest, "encryption_key is required for v0 format")
			return
		}
		userKey, err := base64.StdEncoding.DecodeString(req.EncryptionKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid base64 encryption_key")
			return
		}
		blob, err = SealV0(value, userKey)
		if err != nil {
			log.Errorf("failed to seal v0: %v", err)
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

	case FormatV1:
		userKeys, err := decodeEncryptionKeys(req.EncryptionKeys)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		var version uint64 = 1
		createdAt := time.Now()

		existing, err := h.store.Get(r.Context(), key)
		if err != nil {
			log.Errorf("failed to check existing item: %v", err)
			writeError(w, http.StatusInternalServerError, "storage error")
			return
		}
		if existing != nil {
			meta, err := Metadata(existing)
			if err == nil && meta.FormatVersion == FormatV1 {
				version = meta.ValueVersion + 1
				createdAt = meta.CreatedAt
			}
		}

		blob, err = Seal(value, userKeys, createdAt, version)
		if err != nil {
			log.Errorf("failed to seal v1: %v", err)
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		resp.Version = version
		resp.CreatedAt = createdAt.UTC().Format(time.RFC3339Nano)

	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported format: %d", format))
		return
	}

	if err := h.store.Put(r.Context(), key, blob); err != nil {
		log.Errorf("failed to store: %v", err)
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}

	h.report(r, identity, operationPutObject, map[string]string{
		"format": strconv.Itoa(int(format)),
	})

	writeJSON(w, http.StatusOK, resp)
}

func (h *ItemHandler) handleGet(w http.ResponseWriter, r *http.Request, identity Identity, key string) {
	encKeyB64 := r.Header.Get("X-Encryption-Key")
	if encKeyB64 == "" {
		writeError(w, http.StatusBadRequest, "X-Encryption-Key header is required")
		return
	}

	userKey, err := base64.StdEncoding.DecodeString(encKeyB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 encryption key")
		return
	}

	data, err := h.store.Get(r.Context(), key)
	if err != nil {
		log.Errorf("failed to get: %v", err)
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}
	if data == nil {
		writeError(w, http.StatusNotFound, "item not found")
		return
	}

	plaintext, meta, err := Open(data, userKey)
	if err != nil {
		status := http.StatusInternalServerError
		switch err {
		case ErrKeyNotFound:
			status = http.StatusForbidden
		case ErrDecryptionFailed:
			status = http.StatusForbidden
		case ErrInvalidKeySize:
			status = http.StatusBadRequest
		case ErrInvalidEnvelope:
			status = http.StatusInternalServerError
		}
		writeError(w, status, err.Error())
		return
	}

	resp := GetResponse{
		Value:  base64.StdEncoding.EncodeToString(plaintext),
		Format: meta.FormatVersion,
	}
	if meta.FormatVersion == FormatV1 {
		resp.Version = meta.ValueVersion
		resp.CreatedAt = meta.CreatedAt.UTC().Format(time.RFC3339Nano)
	}

	h.report(r, identity, operationGetObject, map[string]string{
		"format": strconv.Itoa(int(meta.FormatVersion)),
	})

	writeJSON(w, http.StatusOK, resp)
}

func (h *ItemHandler) handleHead(w http.ResponseWriter, r *http.Request, identity Identity, key string) {
	data, err := h.store.Get(r.Context(), key)
	if err != nil {
		log.Errorf("failed to get: %v", err)
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}
	if data == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	meta, err := Metadata(data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "corrupt envelope")
		return
	}

	w.Header().Set("X-Format", strconv.Itoa(int(meta.FormatVersion)))
	if meta.FormatVersion == FormatV1 {
		w.Header().Set("X-Version", strconv.FormatUint(meta.ValueVersion, 10))
		w.Header().Set("X-Created-At", meta.CreatedAt.UTC().Format(time.RFC3339Nano))
		w.Header().Set("X-Num-Encryption-Keys", strconv.Itoa(len(meta.KeySlots)))

		fingerprints := make([]string, len(meta.KeySlots))
		for i, slot := range meta.KeySlots {
			fingerprints[i] = hex.EncodeToString(slot.KeyID[:])
		}
		w.Header().Set("X-Encryption-Key-Fingerprints", strings.Join(fingerprints, ","))
	}

	h.report(r, identity, operationHeadObject, map[string]string{
		"format": strconv.Itoa(int(meta.FormatVersion)),
	})

	w.WriteHeader(http.StatusOK)
}

func (h *ItemHandler) handleDelete(w http.ResponseWriter, r *http.Request, identity Identity, key string) {
	if err := h.store.Delete(r.Context(), key); err != nil {
		log.Errorf("failed to delete: %v", err)
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}

	h.report(r, identity, operationDeleteObject, nil)

	w.WriteHeader(http.StatusNoContent)
}

func (h *ItemHandler) handleAddKey(w http.ResponseWriter, r *http.Request, identity Identity, key string) {
	var req AddKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	existingKey, err := base64.StdEncoding.DecodeString(req.ExistingEncryptionKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 existing_encryption_key")
		return
	}
	newKey, err := base64.StdEncoding.DecodeString(req.NewEncryptionKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 new_encryption_key")
		return
	}

	data, err := h.store.Get(r.Context(), key)
	if err != nil {
		log.Errorf("failed to get: %v", err)
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}
	if data == nil {
		writeError(w, http.StatusNotFound, "item not found")
		return
	}

	updated, err := AddKeySlot(data, existingKey, newKey)
	if err != nil {
		status := http.StatusInternalServerError
		switch err {
		case ErrKeyNotFound, ErrDecryptionFailed:
			status = http.StatusForbidden
		case ErrDuplicateKey:
			status = http.StatusConflict
		case ErrInvalidKeySize:
			status = http.StatusBadRequest
		case ErrV0NoKeySlots:
			status = http.StatusBadRequest
		}
		writeError(w, status, err.Error())
		return
	}

	if err := h.store.Put(r.Context(), key, updated); err != nil {
		log.Errorf("failed to store: %v", err)
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}

	h.report(r, identity, operationAddKey, nil)

	w.WriteHeader(http.StatusNoContent)
}

func (h *ItemHandler) handleRemoveKey(w http.ResponseWriter, r *http.Request, identity Identity, key string) {
	var req RemoveKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	existingKey, err := base64.StdEncoding.DecodeString(req.ExistingEncryptionKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 existing_encryption_key")
		return
	}
	removeKey, err := base64.StdEncoding.DecodeString(req.RemoveEncryptionKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 remove_encryption_key")
		return
	}

	data, err := h.store.Get(r.Context(), key)
	if err != nil {
		log.Errorf("failed to get: %v", err)
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}
	if data == nil {
		writeError(w, http.StatusNotFound, "item not found")
		return
	}

	updated, err := RemoveKeySlot(data, existingKey, removeKey)
	if err != nil {
		status := http.StatusInternalServerError
		switch err {
		case ErrKeyNotFound, ErrDecryptionFailed:
			status = http.StatusForbidden
		case ErrLastKey:
			status = http.StatusConflict
		case ErrInvalidKeySize:
			status = http.StatusBadRequest
		case ErrV0NoKeySlots:
			status = http.StatusBadRequest
		}
		writeError(w, status, err.Error())
		return
	}

	if err := h.store.Put(r.Context(), key, updated); err != nil {
		log.Errorf("failed to store: %v", err)
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}

	h.report(r, identity, operationRemoveKey, nil)

	w.WriteHeader(http.StatusNoContent)
}

func decodeEncryptionKeys(b64Keys []string) ([][]byte, error) {
	if len(b64Keys) == 0 {
		return nil, fmt.Errorf("at least one encryption key is required")
	}
	keys := make([][]byte, len(b64Keys))
	for i, k := range b64Keys {
		decoded, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 encryption key at index %d", i)
		}
		keys[i] = decoded
	}
	return keys, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, ErrorResponse{Error: msg})
}
