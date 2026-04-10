package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	log "github.com/sirupsen/logrus"

	"github.com/tinfoilsh/confidential-kv/crypto"
	"github.com/tinfoilsh/confidential-kv/store"
)

func RegisterTools(server *mcp.Server, r2 *store.R2Store) {
	server.AddTool(kvPutTool(), putHandler(r2))
	server.AddTool(kvGetTool(), getHandler(r2))
	server.AddTool(kvDeleteTool(), deleteHandler(r2))
	server.AddTool(kvListTool(), listHandler(r2))
	server.AddTool(kvAddKeyTool(), addKeyHandler(r2))
	server.AddTool(kvRemoveKeyTool(), removeKeyHandler(r2))
}

func kvPutTool() *mcp.Tool {
	return &mcp.Tool{
		Name:        "kv_put",
		Description: "Store a value encrypted with one or more keys.",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"key":             {Type: "string", Description: "The storage key"},
				"value":           {Type: "string", Description: "Base64-encoded value to store"},
				"encryption_keys": {Type: "array", Description: "Array of base64-encoded 32-byte AES-256 keys (v1)", Items: &jsonschema.Schema{Type: "string"}},
				"encryption_key":  {Type: "string", Description: "Single base64-encoded 32-byte key (v0)"},
				"format":          {Type: "number", Description: "Format version: 0 (direct AES-GCM) or 1 (envelope, default)"},
			},
			Required: []string{"key", "value"},
		},
	}
}

func kvGetTool() *mcp.Tool {
	return &mcp.Tool{
		Name:        "kv_get",
		Description: "Retrieve and decrypt a value using an encryption key.",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"key":            {Type: "string", Description: "The storage key"},
				"encryption_key": {Type: "string", Description: "Base64-encoded 32-byte AES-256 key"},
			},
			Required: []string{"key", "encryption_key"},
		},
	}
}

func kvDeleteTool() *mcp.Tool {
	return &mcp.Tool{
		Name:        "kv_delete",
		Description: "Delete a key from the store.",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"key": {Type: "string", Description: "The storage key to delete"},
			},
			Required: []string{"key"},
		},
	}
}

func kvListTool() *mcp.Tool {
	return &mcp.Tool{
		Name:        "kv_list",
		Description: "List keys matching a prefix.",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"prefix":   {Type: "string", Description: "Key prefix to filter by"},
				"max_keys": {Type: "number", Description: "Maximum number of keys to return (default 100)"},
			},
		},
	}
}

func kvAddKeyTool() *mcp.Tool {
	return &mcp.Tool{
		Name:        "kv_add_key",
		Description: "Add an encryption key slot to an existing value without re-encrypting.",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"key":          {Type: "string", Description: "The storage key"},
				"existing_key": {Type: "string", Description: "Base64-encoded key that can currently decrypt the value"},
				"new_key":      {Type: "string", Description: "Base64-encoded key to add"},
			},
			Required: []string{"key", "existing_key", "new_key"},
		},
	}
}

func kvRemoveKeyTool() *mcp.Tool {
	return &mcp.Tool{
		Name:        "kv_remove_key",
		Description: "Remove an encryption key slot from an existing value.",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"key":          {Type: "string", Description: "The storage key"},
				"existing_key": {Type: "string", Description: "Base64-encoded key that can currently decrypt the value"},
				"remove_key":   {Type: "string", Description: "Base64-encoded key to remove"},
			},
			Required: []string{"key", "existing_key", "remove_key"},
		},
	}
}

type putArgs struct {
	Key            string   `json:"key"`
	Value          string   `json:"value"`
	EncryptionKeys []string `json:"encryption_keys,omitempty"`
	EncryptionKey  string   `json:"encryption_key,omitempty"`
	Format         *float64 `json:"format,omitempty"`
}

type getArgs struct {
	Key           string `json:"key"`
	EncryptionKey string `json:"encryption_key"`
}

type deleteArgs struct {
	Key string `json:"key"`
}

type listArgs struct {
	Prefix  string  `json:"prefix"`
	MaxKeys float64 `json:"max_keys"`
}

type addKeyArgs struct {
	Key         string `json:"key"`
	ExistingKey string `json:"existing_key"`
	NewKey      string `json:"new_key"`
}

type removeKeyArgs struct {
	Key         string `json:"key"`
	ExistingKey string `json:"existing_key"`
	RemoveKey   string `json:"remove_key"`
}

func putHandler(r2 *store.R2Store) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args putArgs
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return toolError("invalid arguments"), nil
		}

		value, err := base64.StdEncoding.DecodeString(args.Value)
		if err != nil {
			return toolError("invalid base64 value"), nil
		}

		format := uint8(crypto.FormatV1)
		if args.Format != nil {
			format = uint8(*args.Format)
		}

		var blob []byte

		switch format {
		case crypto.FormatV0:
			if args.EncryptionKey == "" {
				return toolError("encryption_key is required for v0 format"), nil
			}
			userKey, err := base64.StdEncoding.DecodeString(args.EncryptionKey)
			if err != nil {
				return toolError("invalid base64 encryption_key"), nil
			}
			blob, err = crypto.SealV0(value, userKey)
			if err != nil {
				return toolError(err.Error()), nil
			}

			if err := r2.Put(ctx, args.Key, blob); err != nil {
				log.Errorf("r2 put: %v", err)
				return toolError("storage error"), nil
			}
			return toolText(fmt.Sprintf("stored key=%q format=v0", args.Key)), nil

		case crypto.FormatV1:
			var userKeys [][]byte
			for _, ks := range args.EncryptionKeys {
				decoded, err := base64.StdEncoding.DecodeString(ks)
				if err != nil {
					return toolError("invalid base64 encryption key"), nil
				}
				userKeys = append(userKeys, decoded)
			}
			if len(userKeys) == 0 {
				return toolError("encryption_keys is required for v1 format"), nil
			}

			var version uint64 = 1
			createdAt := time.Now()

			existing, err := r2.Get(ctx, args.Key)
			if err != nil {
				log.Errorf("r2 get: %v", err)
				return toolError("storage error"), nil
			}
			if existing != nil {
				if meta, err := crypto.Metadata(existing); err == nil && meta.FormatVersion == crypto.FormatV1 {
					version = meta.ValueVersion + 1
					createdAt = meta.CreatedAt
				}
			}

			blob, err = crypto.Seal(value, userKeys, createdAt, version)
			if err != nil {
				return toolError(err.Error()), nil
			}

			if err := r2.Put(ctx, args.Key, blob); err != nil {
				log.Errorf("r2 put: %v", err)
				return toolError("storage error"), nil
			}
			return toolText(fmt.Sprintf("stored key=%q version=%d", args.Key, version)), nil

		default:
			return toolError(fmt.Sprintf("unsupported format: %d", format)), nil
		}
	}
}

func getHandler(r2 *store.R2Store) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args getArgs
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return toolError("invalid arguments"), nil
		}

		userKey, err := base64.StdEncoding.DecodeString(args.EncryptionKey)
		if err != nil {
			return toolError("invalid base64 encryption key"), nil
		}

		data, err := r2.Get(ctx, args.Key)
		if err != nil {
			log.Errorf("r2 get: %v", err)
			return toolError("storage error"), nil
		}
		if data == nil {
			return toolError("key not found"), nil
		}

		plaintext, meta, err := crypto.Open(data, userKey)
		if err != nil {
			return toolError(err.Error()), nil
		}

		return toolText(fmt.Sprintf("value=%s version=%d created_at=%s",
			base64.StdEncoding.EncodeToString(plaintext),
			meta.ValueVersion,
			meta.CreatedAt.UTC().Format(time.RFC3339Nano),
		)), nil
	}
}

func deleteHandler(r2 *store.R2Store) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args deleteArgs
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return toolError("invalid arguments"), nil
		}

		if err := r2.Delete(ctx, args.Key); err != nil {
			log.Errorf("r2 delete: %v", err)
			return toolError("storage error"), nil
		}

		return toolText(fmt.Sprintf("deleted key=%q", args.Key)), nil
	}
}

func listHandler(r2 *store.R2Store) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args listArgs
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return toolError("invalid arguments"), nil
		}

		maxKeys := int32(100)
		if args.MaxKeys > 0 {
			maxKeys = int32(args.MaxKeys)
		}

		keys, err := r2.ListKeys(ctx, args.Prefix, maxKeys)
		if err != nil {
			log.Errorf("r2 list: %v", err)
			return toolError("storage error"), nil
		}

		result := fmt.Sprintf("found %d keys", len(keys))
		for _, k := range keys {
			result += "\n" + k
		}
		return toolText(result), nil
	}
}

func addKeyHandler(r2 *store.R2Store) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args addKeyArgs
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return toolError("invalid arguments"), nil
		}

		existingKey, err := base64.StdEncoding.DecodeString(args.ExistingKey)
		if err != nil {
			return toolError("invalid base64 existing_key"), nil
		}
		newKey, err := base64.StdEncoding.DecodeString(args.NewKey)
		if err != nil {
			return toolError("invalid base64 new_key"), nil
		}

		data, err := r2.Get(ctx, args.Key)
		if err != nil {
			log.Errorf("r2 get: %v", err)
			return toolError("storage error"), nil
		}
		if data == nil {
			return toolError("key not found"), nil
		}

		updated, err := crypto.AddKeySlot(data, existingKey, newKey)
		if err != nil {
			return toolError(err.Error()), nil
		}

		if err := r2.Put(ctx, args.Key, updated); err != nil {
			log.Errorf("r2 put: %v", err)
			return toolError("storage error"), nil
		}

		return toolText("key slot added"), nil
	}
}

func removeKeyHandler(r2 *store.R2Store) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args removeKeyArgs
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return toolError("invalid arguments"), nil
		}

		existingKey, err := base64.StdEncoding.DecodeString(args.ExistingKey)
		if err != nil {
			return toolError("invalid base64 existing_key"), nil
		}
		removeKey, err := base64.StdEncoding.DecodeString(args.RemoveKey)
		if err != nil {
			return toolError("invalid base64 remove_key"), nil
		}

		data, err := r2.Get(ctx, args.Key)
		if err != nil {
			log.Errorf("r2 get: %v", err)
			return toolError("storage error"), nil
		}
		if data == nil {
			return toolError("key not found"), nil
		}

		updated, err := crypto.RemoveKeySlot(data, existingKey, removeKey)
		if err != nil {
			return toolError(err.Error()), nil
		}

		if err := r2.Put(ctx, args.Key, updated); err != nil {
			log.Errorf("r2 put: %v", err)
			return toolError("storage error"), nil
		}

		return toolText("key slot removed"), nil
	}
}

func toolText(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

func toolError(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}
}
