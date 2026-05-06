# Confidential Tinfoil Buckets

An encrypted key-value store backed by Cloudflare R2, designed to run inside a [Tinfoil](https://tinfoil.sh) confidential enclave.

Values are encrypted before they reach storage. Clients supply encryption keys with each request, all cryptographic operations happen in-memory inside the enclave, and only ciphertext is persisted.

## Concepts

- **API key** — a tinfoil API key. Identifies _who_ the caller is; resolved against controlplane to a Clerk user (and optional org) used to namespace storage for billing and deletion.
- **accessToken** — an unguessable per-item handle the client picks and uses as the URL path. Identifies _which_ item. Treat it like a password: anyone who knows it can write to it. 36–76 chars, charset `[A-Za-z0-9_-]`.
- **Encryption key** — a 32-byte AES-256 key the client supplies per-request. Never persisted; lives in enclave memory only for the duration of the call.

Items are stored under `{org,user}/{tenantID}/[X-Item-Path/]<accessToken>` in R2.

## Encryption Formats

**v1 (default) — Envelope encryption.** A random DEK encrypts the value with AES-256-GCM. The DEK is wrapped separately under each user-provided key as independent **key slots**, allowing multiple keys per item, key rotation without re-encrypting the value, and version/timestamp tracking.

**v0 (legacy) — Direct encryption.** The user key encrypts the value directly with AES-256-GCM. Simpler, does not support multiple encryption keys or encryption key rotation.

## API

All `/items/*` endpoints require `Authorization: Bearer <api_key>`.

### Store a value — `PUT /items/{accessToken}`

```bash
KEY=$(openssl rand -base64 32)
curl -X PUT http://localhost:8089/items/$ACCESS_TOKEN \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"value\": \"$(echo -n 'hello world' | base64)\", \"encryption_keys\": [\"$KEY\"]}"
```

| Field             | Type     | Description                    |
| ----------------- | -------- | ------------------------------ |
| `value`           | string   | Base64-encoded plaintext       |
| `encryption_keys` | string[] | Base64 32-byte keys (v1)       |
| `encryption_key`  | string   | Single base64 32-byte key (v0) |
| `format`          | int      | `0` or `1` (default: `1`)      |

Response (v1): `{ "version": 1, "created_at": "2026-04-10T12:00:00Z" }`. v0 returns `{}`.

### Retrieve a value — `GET /items/{accessToken}`

```bash
curl http://localhost:8089/items/$ACCESS_TOKEN \
  -H "Authorization: Bearer $API_KEY" \
  -H "X-Encryption-Key: $KEY"
```

Response: `{ "value": "<base64>", "version": 1, "created_at": "...", "format": 1 }`.

### Inspect metadata — `HEAD /items/{accessToken}`

Returns headers without decrypting:

| Header                          | Description                               |
| ------------------------------- | ----------------------------------------- |
| `X-Format`                      | `0` or `1`                                |
| `X-Version`                     | Value version (v1 only)                   |
| `X-Created-At`                  | Creation timestamp (v1 only)              |
| `X-Num-Encryption-Keys`         | Number of key slots (v1 only)             |
| `X-Encryption-Key-Fingerprints` | Comma-separated SHA-256 key IDs (v1 only) |

### Delete — `DELETE /items/{accessToken}`

Returns `204 No Content`.

### Add an encryption key — `POST /items/{accessToken}/encryption-keys`

Adds a new v1 key slot without re-encrypting the value. Requires an existing authorized key.

```json
{ "existing_encryption_key": "<base64>", "new_encryption_key": "<base64>" }
```

### Remove an encryption key — `DELETE /items/{accessToken}/encryption-keys`

Removes a v1 key slot. Cannot remove the last key.

```json
{ "existing_encryption_key": "<base64>", "remove_encryption_key": "<base64>" }
```

### Nested folders — `X-Item-Path` (optional)

Adds caller-defined path segments between the tenant prefix and the `accessToken`, scoping items into folders. Up to 4 slash-separated segments, each 1–36 chars, charset `[A-Za-z0-9_-]`.

```bash
curl ... -H "X-Item-Path: customers/abc/profile"
# stored at user/<userID>/customers/abc/profile/<accessToken>
```

### Health — `GET /health`

Returns `{"status":"ok"}`. No auth required.

## Binary Envelope Format

**v0:** `[0x00] [IV: 12B] [AES-GCM ciphertext + tag]`

**v1:** `[0x01] [num_slots: 2B] [created_at_ms: 8B] [version: 8B] [key_id: 32B | encrypted_dek: 60B] x num_slots [IV: 12B] [AES-GCM ciphertext + tag]`

Each key slot is 92 bytes: SHA-256 fingerprint of the encryption key (32B) + DEK encrypted with that key (IV 12B + ciphertext 32B + GCM tag 16B).

## Configuration

| Variable                              | Default          | Description                           |
| ------------------------------------- | ---------------- | ------------------------------------- |
| `CLOUDFLARE_ACCOUNT_ID`               | required         | Cloudflare account ID                 |
| `R2_TINFOIL_BUCKET_ACCESS_KEY_ID`     | required         | R2 S3 API access key ID               |
| `R2_TINFOIL_BUCKET_SECRET_ACCESS_KEY` | required         | R2 S3 API secret access key           |
| `CONTROLPLANE_URL`                    | required         | Base URL of controlplane for identity |
| `R2_BUCKET_NAME`                      | `tinfoil-bucket` | R2 bucket name                        |
| `LISTEN_ADDR`                         | `:8089`          | HTTP listen address                   |

## Running

```bash
export CLOUDFLARE_ACCOUNT_ID=...
export R2_TINFOIL_BUCKET_ACCESS_KEY_ID=...
export R2_TINFOIL_BUCKET_SECRET_ACCESS_KEY=...
export CONTROLPLANE_URL=https://controlplane.tinfoil.sh
go run .
```

## Security

- Designed for [Tinfoil](https://tinfoil.sh) confidential enclaves — all processing occurs within a trusted execution environment.
- The server never stores plaintext values or encryption keys.
- Encryption keys are supplied per-request and exist in-memory only during the operation.
- AES-256-GCM provides authenticated encryption with 128-bit authentication tags

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on this repository

## License

[AGPL-3.0](LICENSE)
