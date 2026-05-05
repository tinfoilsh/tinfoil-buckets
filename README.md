# Confidential Tinfoil Buckets

An encrypted key value store powered by Cloudflare R2 buckets, designed to run inside a [Tinfoil](https://tinfoil.sh) confidential enclave.

Values are encrypted before they reach storage. Clients supply encryption keys with each request, all cryptographic operations happen in-memory inside the enclave, and then the ciphertext is stored in R2 buckets.

Clients are responsible for remembering their lookup keys.

## Encryption Formats

### v1 (default) -- Envelope Encryption

A random data encryption key (DEK) encrypts the value with AES-256-GCM. The DEK is then wrapped (encrypted) separately under each user-provided key, creating independent **key slots**. This enables:

- Multiple encryption keys for one value
- Adding or removing keys to a KV entry without re-encrypting the value
- Automatic version tracking and creation timestamps

### v0 (legacy) -- Direct Encryption

The user key encrypts the value directly with AES-256-GCM. Simpler, does not support multiple encryption keys or encryption key rotation.

## API

### Store a value

```
PUT /kv/{lookup_key}
```

`{lookup_key}` is required and must be at least 36 characters (UUID-length, to ensure adequate entropy).

```bash
# Generate a 256-bit encryption key
KEY=$(openssl rand -base64 32)

# Store a value (v1, default)
curl -X PUT http://localhost:8089/kv/my-lookup-key \
  -H "Content-Type: application/json" \
  -d "{
    \"value\": \"$(echo -n 'hello world' | base64)\",
    \"encryption_keys\": [\"$KEY\"]
  }"
```

**Request body:**

| Field             | Type     | Description                                       |
| ----------------- | -------- | ------------------------------------------------- |
| `value`           | string   | Base64-encoded plaintext                          |
| `encryption_keys` | string[] | Base64-encoded 32-byte encryption keys (v1)       |
| `encryption_key`  | string   | Single base64-encoded 32-byte encryption key (v0) |
| `format`          | int      | `0` or `1` (default: `1`)                         |

**Response:**

```json
{
  "lookup_key": "my-lookup-key",
  "version": 1,
  "created_at": "2026-04-10T12:00:00.000Z"
}
```

### Retrieve a value

```
GET /kv/{lookup_key}
```

```bash
curl http://localhost:8089/kv/my-lookup-key \
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
HEAD /kv/{lookup_key}
```

Returns headers without decrypting the value:

| Header                          | Description                                          |
| ------------------------------- | ---------------------------------------------------- |
| `X-Format`                      | `0` or `1`                                           |
| `X-Version`                     | Value version (v1 only)                              |
| `X-Created-At`                  | Creation timestamp (v1 only)                         |
| `X-Num-Encryption-Keys`         | Number of encryption-key slots (v1 only)             |
| `X-Encryption-Key-Fingerprints` | Comma-separated SHA-256 encryption-key IDs (v1 only) |

### Delete a value

```
DELETE /kv/{lookup_key}
```

Returns `204 No Content`.

### Add an encryption key

```
POST /kv/{lookup_key}/encryption-keys
```

Adds a new key slot to a v1 envelope without re-encrypting the value. Requires an existing authorized encryption key to unwrap the DEK.

```json
{
  "existing_encryption_key": "<base64 encryption key that can currently decrypt>",
  "new_encryption_key": "<base64 encryption key to add>"
}
```

### Remove an encryption key

```
DELETE /kv/{lookup_key}/encryption-keys
```

Removes a key slot from a v1 envelope. Cannot remove the last encryption key.

```json
{
  "existing_encryption_key": "<base64 encryption key that can currently decrypt>",
  "remove_encryption_key": "<base64 encryption key to remove>"
}
```

### Health check

```
GET /health
```

Returns `{"status":"ok"}`.

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

Each key slot is 92 bytes: a SHA-256 fingerprint of the encryption key (32B) followed by the DEK encrypted with that encryption key (IV 12B + ciphertext 32B + GCM tag 16B).

## Configuration

| Variable                | Default    | Description           |
| ----------------------- | ---------- | --------------------- |
| `CLOUDFLARE_ACCOUNT_ID` | required   | Cloudflare account ID |
| `CLOUDFLARE_API_TOKEN`  | required   | Cloudflare API token  |
| `R2_BUCKET_NAME`        | `kv-store` | R2 bucket name        |
| `LISTEN_ADDR`           | `:8089`    | HTTP listen address   |

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
- Clients supply encryption keys per-request; keys exist in-memory only during the operation
- All cryptography uses Go's standard library (`crypto/aes`, `crypto/cipher`, `crypto/rand`)
- AES-256-GCM provides authenticated encryption with 128-bit authentication tags

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on this repository

## License

[AGPL-3.0](LICENSE)
