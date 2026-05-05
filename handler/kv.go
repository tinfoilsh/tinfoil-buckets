package handler

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/tinfoilsh/confidential-kv/crypto"
	"github.com/tinfoilsh/confidential-kv/store"
)

type KVHandler struct {
	store *store.R2Store
}

func NewKVHandler(store *store.R2Store) *KVHandler {
	return &KVHandler{store: store}
}

// PUT /kv/{key}
type PutRequest struct {
	Value          string   `json:"value"`                     // base64-encoded
	EncryptionKeys []string `json:"encryption_keys,omitempty"` // base64-encoded 32-byte keys (required for v1)
	EncryptionKey  string   `json:"encryption_key,omitempty"`  // single base64 key (required for v0)
	Format         *int     `json:"format,omitempty"`          // 0 or 1 (default: 1)
}

type PutResponse struct {
	Key       string `json:"key"`
	Version   uint64 `json:"version,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// POST /kv/{key}/keys
type AddKeyRequest struct {
	ExistingKey string `json:"existing_key"` // base64
	NewKey      string `json:"new_key"`      // base64
}

// DELETE /kv/{key}/keys
type RemoveKeyRequest struct {
	ExistingKey string `json:"existing_key"` // base64
	RemoveKey   string `json:"remove_key"`   // base64
}

// GET /kv/{key} response
type GetResponse struct {
	Value     string `json:"value"`                // base64-encoded
	Version   uint64 `json:"version,omitempty"`    // v1 only
	CreatedAt string `json:"created_at,omitempty"` // v1 only
	Format    uint8  `json:"format"`
}

// HEAD /kv/{key} metadata
type HeadResponse struct {
	Version   uint64 `json:"version"`
	CreatedAt string `json:"created_at"`
	NumKeys   int    `json:"num_keys"`
}

// GET /kv/?prefix=&max_keys= response
type ListResponse struct {
	Keys []string `json:"keys"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func (h *KVHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Route: /kv/{key} or /kv/{key}/keys
	path := r.URL.Path
	if !strings.HasPrefix(path, "/kv/") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	rest := path[4:] // everything after "/kv/"

	// Check if it's a /keys sub-route
	if idx := lastIndex(rest, "/keys"); idx >= 0 && idx+5 == len(rest) {
		key := rest[:idx]
		if key == "" {
			writeError(w, http.StatusBadRequest, "key is required")
			return
		}
		switch r.Method {
		case http.MethodPost:
			h.handleAddKey(w, r, key)
		case http.MethodDelete:
			h.handleRemoveKey(w, r, key)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}

	key := rest

	switch r.Method {
	case http.MethodPut:
		if key == "" {
			key = uuid.New().String()
		}
		h.handlePut(w, r, key)
	case http.MethodGet:
		if key == "" {
			h.handleList(w, r)
			return
		}
		h.handleGet(w, r, key)
	case http.MethodHead:
		if key == "" {
			writeError(w, http.StatusBadRequest, "key is required")
			return
		}
		h.handleHead(w, r, key)
	case http.MethodDelete:
		if key == "" {
			writeError(w, http.StatusBadRequest, "key is required")
			return
		}
		h.handleDelete(w, r, key)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *KVHandler) handlePut(w http.ResponseWriter, r *http.Request, key string) {
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

	format := uint8(crypto.FormatV1)
	if req.Format != nil {
		format = uint8(*req.Format)
	}

	var blob []byte

	switch format {
	case crypto.FormatV0:
		if req.EncryptionKey == "" {
			writeError(w, http.StatusBadRequest, "encryption_key is required for v0 format")
			return
		}
		userKey, err := base64.StdEncoding.DecodeString(req.EncryptionKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid base64 encryption_key")
			return
		}
		blob, err = crypto.SealV0(value, userKey)
		if err != nil {
			log.Errorf("failed to seal v0: %v", err)
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

	case crypto.FormatV1:
		userKeys, err := decodeKeys(req.EncryptionKeys)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		var version uint64 = 1
		createdAt := time.Now()

		existing, err := h.store.Get(r.Context(), key)
		if err != nil {
			log.Errorf("failed to check existing key: %v", err)
			writeError(w, http.StatusInternalServerError, "storage error")
			return
		}
		if existing != nil {
			meta, err := crypto.Metadata(existing)
			if err == nil && meta.FormatVersion == crypto.FormatV1 {
				version = meta.ValueVersion + 1
				createdAt = meta.CreatedAt
			}
		}

		blob, err = crypto.Seal(value, userKeys, createdAt, version)
		if err != nil {
			log.Errorf("failed to seal v1: %v", err)
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		if err := h.store.Put(r.Context(), key, blob); err != nil {
			log.Errorf("failed to store: %v", err)
			writeError(w, http.StatusInternalServerError, "storage error")
			return
		}

		writeJSON(w, http.StatusOK, PutResponse{
			Key:       key,
			Version:   version,
			CreatedAt: createdAt.UTC().Format(time.RFC3339Nano),
		})
		return

	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported format: %d", format))
		return
	}

	if err := h.store.Put(r.Context(), key, blob); err != nil {
		log.Errorf("failed to store: %v", err)
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}

	writeJSON(w, http.StatusOK, PutResponse{Key: key})
}

func (h *KVHandler) handleGet(w http.ResponseWriter, r *http.Request, key string) {
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
		writeError(w, http.StatusNotFound, "key not found")
		return
	}

	plaintext, meta, err := crypto.Open(data, userKey)
	if err != nil {
		status := http.StatusInternalServerError
		switch err {
		case crypto.ErrKeyNotFound:
			status = http.StatusForbidden
		case crypto.ErrDecryptionFailed:
			status = http.StatusForbidden
		case crypto.ErrInvalidKeySize:
			status = http.StatusBadRequest
		case crypto.ErrInvalidEnvelope:
			status = http.StatusInternalServerError
		}
		writeError(w, status, err.Error())
		return
	}

	resp := GetResponse{
		Value:  base64.StdEncoding.EncodeToString(plaintext),
		Format: meta.FormatVersion,
	}
	if meta.FormatVersion == crypto.FormatV1 {
		resp.Version = meta.ValueVersion
		resp.CreatedAt = meta.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *KVHandler) handleHead(w http.ResponseWriter, r *http.Request, key string) {
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

	meta, err := crypto.Metadata(data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "corrupt envelope")
		return
	}

	w.Header().Set("X-Format", strconv.Itoa(int(meta.FormatVersion)))
	if meta.FormatVersion == crypto.FormatV1 {
		w.Header().Set("X-Version", strconv.FormatUint(meta.ValueVersion, 10))
		w.Header().Set("X-Created-At", meta.CreatedAt.UTC().Format(time.RFC3339Nano))
		w.Header().Set("X-Num-Keys", strconv.Itoa(len(meta.KeySlots)))

		fingerprints := make([]string, len(meta.KeySlots))
		for i, slot := range meta.KeySlots {
			fingerprints[i] = hex.EncodeToString(slot.KeyID[:])
		}
		w.Header().Set("X-Key-Fingerprints", strings.Join(fingerprints, ","))
	}
	w.WriteHeader(http.StatusOK)
}

func (h *KVHandler) handleDelete(w http.ResponseWriter, r *http.Request, key string) {
	if err := h.store.Delete(r.Context(), key); err != nil {
		log.Errorf("failed to delete: %v", err)
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *KVHandler) handleList(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")

	maxKeys := int32(100)
	if v := r.URL.Query().Get("max_keys"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "max_keys must be a positive integer")
			return
		}
		maxKeys = int32(n)
	}

	keys, err := h.store.ListKeys(r.Context(), prefix, maxKeys)
	if err != nil {
		log.Errorf("failed to list: %v", err)
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}
	if keys == nil {
		keys = []string{}
	}
	writeJSON(w, http.StatusOK, ListResponse{Keys: keys})
}

func (h *KVHandler) handleAddKey(w http.ResponseWriter, r *http.Request, key string) {
	var req AddKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	existingKey, err := base64.StdEncoding.DecodeString(req.ExistingKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 existing_key")
		return
	}
	newKey, err := base64.StdEncoding.DecodeString(req.NewKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 new_key")
		return
	}

	data, err := h.store.Get(r.Context(), key)
	if err != nil {
		log.Errorf("failed to get: %v", err)
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}
	if data == nil {
		writeError(w, http.StatusNotFound, "key not found")
		return
	}

	updated, err := crypto.AddKeySlot(data, existingKey, newKey)
	if err != nil {
		status := http.StatusInternalServerError
		switch err {
		case crypto.ErrKeyNotFound, crypto.ErrDecryptionFailed:
			status = http.StatusForbidden
		case crypto.ErrDuplicateKey:
			status = http.StatusConflict
		case crypto.ErrInvalidKeySize:
			status = http.StatusBadRequest
		case crypto.ErrV0NoKeySlots:
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

	w.WriteHeader(http.StatusNoContent)
}

func (h *KVHandler) handleRemoveKey(w http.ResponseWriter, r *http.Request, key string) {
	var req RemoveKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	existingKey, err := base64.StdEncoding.DecodeString(req.ExistingKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 existing_key")
		return
	}
	removeKey, err := base64.StdEncoding.DecodeString(req.RemoveKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 remove_key")
		return
	}

	data, err := h.store.Get(r.Context(), key)
	if err != nil {
		log.Errorf("failed to get: %v", err)
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}
	if data == nil {
		writeError(w, http.StatusNotFound, "key not found")
		return
	}

	updated, err := crypto.RemoveKeySlot(data, existingKey, removeKey)
	if err != nil {
		status := http.StatusInternalServerError
		switch err {
		case crypto.ErrKeyNotFound, crypto.ErrDecryptionFailed:
			status = http.StatusForbidden
		case crypto.ErrLastKey:
			status = http.StatusConflict
		case crypto.ErrInvalidKeySize:
			status = http.StatusBadRequest
		case crypto.ErrV0NoKeySlots:
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

	w.WriteHeader(http.StatusNoContent)
}

func decodeKeys(b64Keys []string) ([][]byte, error) {
	if len(b64Keys) == 0 {
		return nil, fmt.Errorf("at least one encryption key is required")
	}
	keys := make([][]byte, len(b64Keys))
	for i, k := range b64Keys {
		decoded, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 key at index %d", i)
		}
		keys[i] = decoded
	}
	return keys, nil
}

func lastIndex(s, substr string) int {
	for i := len(s) - len(substr); i >= 0; i-- {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, ErrorResponse{Error: msg})
}
