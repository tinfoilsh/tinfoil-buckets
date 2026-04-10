# Confidential KV

An encrypted key-value store backed by Cloudflare R2, designed to run inside a [Tinfoil](https://tinfoil.sh) confidential enclave.

Values are encrypted before they reach storage. The server never persists plaintext -- clients supply their encryption keys with each request, and all cryptographic operations happen in-memory inside the enclave.

## Encryption Formats

### v1 (default) -- Envelope Encryption

A random data encryption key (DEK) encrypts the value with AES-256-GCM. The DEK is then wrapped (encrypted) separately under each user-provided key, creating independent **key slots**. This enables:

- Multiple users/keys per value
- Adding or removing keys without re-encrypting the value
- Automatic version tracking and creation timestamps

### v0 -- Direct Encryption

The user key encrypts the value directly with AES-256-GCM. Simpler, but does not support multiple keys or key rotation.

## API

### Store a value

```
PUT /kv/{key}
```

If `{key}` is omitted, a UUID is generated.

```bash
# Generate a 256-bit key
KEY=$(openssl rand -base64 32)

# Store a value (v1, default)
curl -X PUT http://localhost:8089/kv/my-key \
  -H "Content-Type: application/json" \
  -d "{
    \"value\": \"$(echo -n 'hello world' | base64)\",
    \"encryption_keys\": [\"$KEY\"]
  }"
```

**Request body:**

| Field | Type | Description |
|-------|------|-------------|
| `value` | string | Base64-encoded plaintext |
| `encryption_keys` | string[] | Base64-encoded 32-byte keys (v1) |
| `encryption_key` | string | Single base64-encoded 32-byte key (v0) |
| `format` | int | `0` or `1` (default: `1`) |

**Response:**

```json
{
  "key": "my-key",
  "version": 1,
  "created_at": "2026-04-10T12:00:00.000Z"
}
```

### Retrieve a value

```
GET /kv/{key}
```

```bash
curl http://localhost:8089/kv/my-key \
  -H "X-Encryption-Key: $KEY"
```

**Response:**

```json
{
  "value": "aGVsbG8gd29ybGQ=",
  "version": 1,
  "created_at": "2026-04-10T12:00:00.000Z",
  "format": 1
}
```

### Inspect metadata

```
HEAD /kv/{key}
```

Returns headers without decrypting the value:

| Header | Description |
|--------|-------------|
| `X-Format` | `0` or `1` |
| `X-Version` | Value version (v1 only) |
| `X-Created-At` | Creation timestamp (v1 only) |
| `X-Num-Keys` | Number of key slots (v1 only) |
| `X-Key-Fingerprints` | Comma-separated SHA-256 key IDs (v1 only) |

### Delete a value

```
DELETE /kv/{key}
```

Returns `204 No Content`.

### Add an encryption key

```
POST /kv/{key}/keys
```

Adds a new key slot to a v1 envelope without re-encrypting the value. Requires an existing authorized key to unwrap the DEK.

```json
{
  "existing_key": "<base64 key that can currently decrypt>",
  "new_key": "<base64 key to add>"
}
```

### Remove an encryption key

```
DELETE /kv/{key}/keys
```

Removes a key slot from a v1 envelope. Cannot remove the last key.

```json
{
  "existing_key": "<base64 key that can currently decrypt>",
  "remove_key": "<base64 key to remove>"
}
```

### Health check

```
GET /health
```

Returns `{"status":"ok"}`.

## MCP

The server exposes an [MCP](https://modelcontextprotocol.io) endpoint at `POST /mcp` with the following tools:

| Tool | Description |
|------|-------------|
| `kv_put` | Store a value encrypted with one or more keys |
| `kv_get` | Retrieve and decrypt a value |
| `kv_delete` | Delete a key |
| `kv_list` | List keys matching a prefix |
| `kv_add_key` | Add an encryption key slot to an existing value |
| `kv_remove_key` | Remove an encryption key slot |

## Binary Envelope Format

### v0

```
[0x00] [IV: 12B] [AES-GCM ciphertext + tag]
```

### v1

```
[0x01] [num_slots: 2B] [created_at_ms: 8B] [version: 8B]
[key_id: 32B | encrypted_dek: 60B] x num_slots
[IV: 12B] [AES-GCM ciphertext + tag]
```

Each key slot is 92 bytes: a SHA-256 fingerprint of the user key (32B) followed by the DEK encrypted with that user key (IV 12B + ciphertext 32B + GCM tag 16B).

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CLOUDFLARE_ACCOUNT_ID` | required | Cloudflare account ID |
| `CLOUDFLARE_API_TOKEN` | required | Cloudflare API token |
| `R2_BUCKET_NAME` | `kv-store` | R2 bucket name |
| `LISTEN_ADDR` | `:8089` | HTTP listen address |

## Running

```bash
export CLOUDFLARE_ACCOUNT_ID="your-account-id"
export CLOUDFLARE_API_TOKEN="your-api-token"

go run .
```

### Docker

```bash
docker build -t confidential-kv .
docker run -p 8089:8089 \
  -e CLOUDFLARE_ACCOUNT_ID=$CLOUDFLARE_ACCOUNT_ID \
  -e CLOUDFLARE_API_TOKEN=$CLOUDFLARE_API_TOKEN \
  confidential-kv
```

## Security

- Designed for [Tinfoil](https://tinfoil.sh) confidential enclaves -- all processing occurs within a trusted execution environment
- The server never stores plaintext values or encryption keys
- Clients supply keys per-request; keys exist in-memory only during the operation
- All cryptography uses Go's standard library (`crypto/aes`, `crypto/cipher`, `crypto/rand`)
- AES-256-GCM provides authenticated encryption with 128-bit authentication tags

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on this repository

## License

[AGPL-3.0](LICENSE)
