# Fastly Blossom Server Design

## Overview

A Blossom-compliant media server for Nostr, optimized for video, running on Fastly Compute in Rust.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              Fastly Compute (Rust)                          │
│                                                             │
│  • Blossom API (BUD-01, BUD-02, BUD-03)                    │
│  • Nostr auth validation (kind 24242)                      │
│  • S3 signing for B2                                        │
│  • Range requests (native)                                  │
│  • Edge caching                                             │
└─────────────────────────────────────────────────────────────┘
                          │
            ┌─────────────┴─────────────┐
            ▼                           ▼
   ┌─────────────────┐        ┌─────────────────┐
   │  Backblaze B2   │        │   Fastly KV     │
   │  (blobs)        │        │   (metadata)    │
   │                 │        │                 │
   │  free egress    │        │  blob:<hash>    │
   └────────┬────────┘        │  list:<pubkey>  │
            │                 └─────────────────┘
            │ async
            ▼
   ┌─────────────────┐
   │  GCP            │
   │  (moderation)   │
   │                 │
   │  Video AI       │
   └─────────────────┘
```

## Scope (v1)

### Included
- BUD-01: Server requirements and blob retrieval (GET/HEAD)
- BUD-02: Blob upload and management (PUT/DELETE/list)
- BUD-03: User server list support (kind 10063)

### Excluded (future)
- BUD-04: Mirroring
- BUD-05: Media optimization / transcoding
- BUD-07: Payments

## Storage

### Primary: Backblaze B2
- S3-compatible API
- Free egress to Fastly
- Blobs stored as: `<bucket>/<sha256>`

### Metadata: Fastly KV Store

Two key patterns:

```
blob:<sha256> → {
    "sha256": "abc123...",
    "size": 12345678,
    "type": "video/mp4",
    "uploaded": "2024-01-15T10:30:00Z",
    "owner": "<pubkey>",
    "status": "active" | "restricted" | "pending"
}

list:<pubkey> → ["sha256_1", "sha256_2", ...]
```

## Moderation

Flow: Upload → B2 → async replicate to GCP → Video AI analysis → update KV status

Status values:
- `active`: Normal serving
- `restricted`: Shadow restricted (serve only to owner with auth)
- `pending`: Awaiting moderation review

## Authentication

Nostr kind 24242 events for authorization:

```json
{
  "kind": 24242,
  "content": "Upload blob",
  "tags": [
    ["t", "upload"],
    ["x", "<sha256>"],
    ["expiration", "<unix_timestamp>"]
  ]
}
```

Sent as: `Authorization: Nostr <base64_encoded_event>`

Validation:
1. Decode base64 event
2. Verify secp256k1 signature
3. Check expiration
4. Match action tag ("upload", "delete", "list")
5. Match hash tag for delete operations

## API Endpoints

### BUD-01: Retrieval

| Method | Path | Description |
|--------|------|-------------|
| GET | `/<sha256>[.ext]` | Retrieve blob |
| HEAD | `/<sha256>[.ext]` | Check blob existence |

### BUD-02: Management

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/upload` | Required | Upload blob |
| HEAD | `/upload` | None | Get upload requirements |
| DELETE | `/<sha256>` | Required | Delete blob |
| GET | `/list/<pubkey>` | Optional | List user's blobs |

## Request Flows

### Upload
1. Validate Nostr auth (kind 24242, t=upload)
2. Stream body, compute SHA-256
3. Sign request with AWS v4
4. PUT to B2
5. Store metadata in KV (status=pending)
6. Trigger async moderation
7. Return BlobDescriptor

### Retrieval
1. Parse SHA-256 from path
2. Check KV metadata
3. If restricted: require auth, verify owner
4. Sign GET to B2
5. Stream response (range support automatic)

### Delete
1. Validate Nostr auth (kind 24242, t=delete, x=<hash>)
2. Verify ownership in KV
3. Delete from B2
4. Remove from KV

## Configuration

### fastly.toml
```toml
[local_server.backends.b2]
url = "https://s3.us-west-004.backblazeb2.com"

[local_server.kv_stores.blossom-meta]
```

### Environment/Secrets
- `B2_KEY_ID`: Backblaze application key ID
- `B2_APP_KEY`: Backblaze application key
- `B2_BUCKET`: Bucket name
- `B2_REGION`: e.g., us-west-004

## Project Structure

```
fastly-blossom/
├── Cargo.toml
├── fastly.toml
├── rust-toolchain.toml
├── src/
│   ├── main.rs           # Entry point, request routing
│   ├── auth.rs           # Nostr kind 24242 validation
│   ├── storage.rs        # B2 S3 operations
│   ├── metadata.rs       # Fastly KV store operations
│   ├── blossom.rs        # Protocol types & responses
│   └── error.rs          # Error handling
└── docs/
    └── plans/
```
