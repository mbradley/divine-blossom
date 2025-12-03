# GCS Migration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Migrate Fastly Blossom from Backblaze B2 to Google Cloud Storage with HMAC authentication and resumable upload support.

**Architecture:** GCS S3-compatible API with HMAC keys reusing existing AWS v4 signing. Large files (>5MB) use multipart uploads. Cloud Function handles async content moderation.

**Tech Stack:** Rust/WASM (Fastly Compute), GCS S3-compat API, AWS v4 signing, Python (Cloud Function)

**Design Reference:** `docs/plans/2025-12-03-gcs-migration-design.md`

---

## Phase 1: GCS Storage Configuration

### Task 1: Update Storage Constants and Config Struct

**Files:**
- Modify: `src/storage.rs:12-74`

**Step 1: Update backend and host constants**

In `src/storage.rs`, change the constants at the top of the file:

```rust
// ABOUTME: Google Cloud Storage operations via S3-compatible API
// ABOUTME: Implements AWS v4 signing with GCS HMAC authentication

use crate::error::{BlossomError, Result};
use fastly::http::{Method, StatusCode};
use fastly::{Body, Request, Response};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Backend name (must match fastly.toml)
const GCS_BACKEND: &str = "gcs_storage";

/// Config store name
const CONFIG_STORE: &str = "blossom_config";

/// Secret store name
const SECRET_STORE: &str = "blossom_secrets";

/// AWS signature version (works with GCS HMAC)
const AWS_ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// S3 service name (GCS uses s3 for S3-compat mode)
const SERVICE: &str = "s3";

/// GCS region for signing (use "auto" for path-style)
const GCS_REGION: &str = "auto";

/// Multipart upload threshold (5MB)
const MULTIPART_THRESHOLD: u64 = 5 * 1024 * 1024;

/// Part size for multipart uploads (5MB)
const PART_SIZE: u64 = 5 * 1024 * 1024;
```

**Step 2: Update config struct and load function**

Replace `B2Config` struct with `GCSConfig`:

```rust
/// GCS configuration
struct GCSConfig {
    access_key: String,    // HMAC access key
    secret_key: String,    // HMAC secret key
    bucket: String,
}

impl GCSConfig {
    fn load() -> Result<Self> {
        Ok(GCSConfig {
            access_key: get_secret("gcs_access_key")?,
            secret_key: get_secret("gcs_secret_key")?,
            bucket: get_config("gcs_bucket")?,
        })
    }

    fn host(&self) -> String {
        "storage.googleapis.com".to_string()
    }

    fn endpoint(&self) -> String {
        format!("https://{}", self.host())
    }

    fn region(&self) -> &str {
        GCS_REGION
    }
}
```

**Step 3: Build and verify compilation**

Run:
```bash
cd /Users/rabble/code/divine/fastly-blossom-gcs && fastly compute build 2>&1
```
Expected: SUCCESS (with warnings about unused functions temporarily)

**Step 4: Commit**

```bash
git add src/storage.rs
git commit -m "refactor(storage): update config for GCS HMAC authentication

- Change backend from b2_s3 to gcs_storage
- Replace B2Config with GCSConfig struct
- Update host to storage.googleapis.com
- Add multipart upload constants"
```

---

### Task 2: Update Storage Functions for GCS

**Files:**
- Modify: `src/storage.rs:76-173`

**Step 1: Update upload_blob function**

Change all references from `config` region to use `config.region()`:

```rust
/// Upload a blob to GCS (simple PUT for small files)
pub fn upload_blob(hash: &str, body: Body, content_type: &str, size: u64) -> Result<()> {
    let config = GCSConfig::load()?;

    // For large files, use multipart upload
    if size > MULTIPART_THRESHOLD {
        return upload_blob_multipart(hash, body, content_type, size);
    }

    let path = format!("/{}/{}", config.bucket, hash);

    let mut req = Request::new(Method::PUT, format!("{}{}", config.endpoint(), path));
    req.set_header("Content-Type", content_type);
    req.set_header("Content-Length", size.to_string());
    req.set_header("Host", config.host());

    // Sign the request
    sign_request(&mut req, &config, Some(hash_body_for_signing(size)))?;

    req.set_body(body);

    let resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to upload: {}", e)))?;

    if !resp.get_status().is_success() {
        return Err(BlossomError::StorageError(format!(
            "Upload failed with status: {}",
            resp.get_status()
        )));
    }

    Ok(())
}
```

**Step 2: Update download_blob function**

```rust
/// Download a blob from GCS (returns the response to stream back)
pub fn download_blob(hash: &str, range: Option<&str>) -> Result<Response> {
    let config = GCSConfig::load()?;
    let path = format!("/{}/{}", config.bucket, hash);

    let mut req = Request::new(Method::GET, format!("{}{}", config.endpoint(), path));
    req.set_header("Host", config.host());

    if let Some(range_value) = range {
        req.set_header("Range", range_value);
    }

    // Sign the request
    sign_request(&mut req, &config, Some("UNSIGNED-PAYLOAD".into()))?;

    let resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to download: {}", e)))?;

    match resp.get_status() {
        StatusCode::OK | StatusCode::PARTIAL_CONTENT => Ok(resp),
        StatusCode::NOT_FOUND => Err(BlossomError::NotFound("Blob not found in storage".into())),
        status => Err(BlossomError::StorageError(format!(
            "Download failed with status: {}",
            status
        ))),
    }
}
```

**Step 3: Update blob_exists function**

```rust
/// Check if a blob exists in GCS
pub fn blob_exists(hash: &str) -> Result<bool> {
    let config = GCSConfig::load()?;
    let path = format!("/{}/{}", config.bucket, hash);

    let mut req = Request::new(Method::HEAD, format!("{}{}", config.endpoint(), path));
    req.set_header("Host", config.host());

    sign_request(&mut req, &config, Some("UNSIGNED-PAYLOAD".into()))?;

    let resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to check blob: {}", e)))?;

    Ok(resp.get_status() == StatusCode::OK)
}
```

**Step 4: Update delete_blob function**

```rust
/// Delete a blob from GCS
pub fn delete_blob(hash: &str) -> Result<()> {
    let config = GCSConfig::load()?;
    let path = format!("/{}/{}", config.bucket, hash);

    let mut req = Request::new(Method::DELETE, format!("{}{}", config.endpoint(), path));
    req.set_header("Host", config.host());

    sign_request(&mut req, &config, Some("UNSIGNED-PAYLOAD".into()))?;

    let resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to delete: {}", e)))?;

    if !resp.get_status().is_success() && resp.get_status() != StatusCode::NOT_FOUND {
        return Err(BlossomError::StorageError(format!(
            "Delete failed with status: {}",
            resp.get_status()
        )));
    }

    Ok(())
}
```

**Step 5: Build and verify**

Run:
```bash
cd /Users/rabble/code/divine/fastly-blossom-gcs && fastly compute build 2>&1
```
Expected: SUCCESS

**Step 6: Commit**

```bash
git add src/storage.rs
git commit -m "refactor(storage): update all storage functions for GCS

- Update upload_blob with multipart threshold check
- Update download_blob, blob_exists, delete_blob
- Change backend constant usage to GCS_BACKEND"
```

---

### Task 3: Update Signing Function for GCS

**Files:**
- Modify: `src/storage.rs:240-309`

**Step 1: Update sign_request to use GCSConfig**

The signing logic stays the same (AWS v4 works with GCS HMAC), just update the config reference:

```rust
/// AWS v4 request signing (works with GCS HMAC)
fn sign_request(req: &mut Request, config: &GCSConfig, payload_hash: Option<String>) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = now.as_secs();
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_ymd(days_since_epoch);

    let date_stamp = format!("{:04}{:02}{:02}", year, month, day);
    let amz_date = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        year, month, day, hours, minutes, seconds
    );

    // Set required headers
    req.set_header("x-amz-date", &amz_date);

    let payload_hash = payload_hash.unwrap_or_else(|| "UNSIGNED-PAYLOAD".into());
    req.set_header("x-amz-content-sha256", &payload_hash);

    // Create canonical request
    let method = req.get_method_str();
    let uri = req.get_path();
    let query = req.get_query_str().unwrap_or("");

    let host = config.host();
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
        host, payload_hash, amz_date
    );

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, uri, query, canonical_headers, signed_headers, payload_hash
    );

    // Create string to sign
    let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, config.region(), SERVICE);

    let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));

    let string_to_sign = format!(
        "{}\n{}\n{}\n{}",
        AWS_ALGORITHM, amz_date, credential_scope, canonical_request_hash
    );

    // Calculate signature
    let signing_key = get_signing_key(&config.secret_key, &date_stamp, config.region())?;
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);

    // Create authorization header
    let authorization = format!(
        "{} Credential={}/{}, SignedHeaders={}, Signature={}",
        AWS_ALGORITHM, config.access_key, credential_scope, signed_headers, signature
    );

    req.set_header("Authorization", authorization);

    Ok(())
}
```

**Step 2: Build and verify**

Run:
```bash
cd /Users/rabble/code/divine/fastly-blossom-gcs && fastly compute build 2>&1
```
Expected: SUCCESS

**Step 3: Commit**

```bash
git add src/storage.rs
git commit -m "refactor(storage): update sign_request for GCSConfig

- Change parameter type from B2Config to GCSConfig
- Use config.region() for credential scope"
```

---

## Phase 2: Multipart Upload Support

### Task 4: Add Multipart Upload Initiation

**Files:**
- Modify: `src/storage.rs` (add after delete_blob function)

**Step 1: Add multipart upload initiation function**

```rust
/// Initiate a multipart upload to GCS
fn initiate_multipart_upload(hash: &str, content_type: &str) -> Result<String> {
    let config = GCSConfig::load()?;
    let path = format!("/{}/{}?uploads", config.bucket, hash);

    let mut req = Request::new(Method::POST, format!("{}{}", config.endpoint(), path));
    req.set_header("Host", config.host());
    req.set_header("Content-Type", content_type);
    req.set_header("Content-Length", "0");

    sign_request(&mut req, &config, Some("UNSIGNED-PAYLOAD".into()))?;

    let mut resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to initiate multipart: {}", e)))?;

    if !resp.get_status().is_success() {
        return Err(BlossomError::StorageError(format!(
            "Initiate multipart failed with status: {}",
            resp.get_status()
        )));
    }

    // Parse XML response to get UploadId
    let body = resp.take_body().into_string();

    // Simple XML parsing for UploadId
    let upload_id = extract_upload_id(&body)
        .ok_or_else(|| BlossomError::StorageError("Failed to parse UploadId from response".into()))?;

    Ok(upload_id)
}

/// Extract UploadId from XML response
fn extract_upload_id(xml: &str) -> Option<String> {
    // Look for <UploadId>...</UploadId>
    let start_tag = "<UploadId>";
    let end_tag = "</UploadId>";

    let start = xml.find(start_tag)? + start_tag.len();
    let end = xml[start..].find(end_tag)? + start;

    Some(xml[start..end].to_string())
}
```

**Step 2: Build and verify**

Run:
```bash
cd /Users/rabble/code/divine/fastly-blossom-gcs && fastly compute build 2>&1
```
Expected: SUCCESS (warnings about unused functions OK)

**Step 3: Commit**

```bash
git add src/storage.rs
git commit -m "feat(storage): add multipart upload initiation

- Add initiate_multipart_upload function
- Add XML parser for UploadId extraction"
```

---

### Task 5: Add Upload Part Function

**Files:**
- Modify: `src/storage.rs` (add after initiate_multipart_upload)

**Step 1: Add upload part function**

```rust
/// Upload a single part of a multipart upload
fn upload_part(
    hash: &str,
    upload_id: &str,
    part_number: u32,
    body: &[u8],
) -> Result<String> {
    let config = GCSConfig::load()?;
    let path = format!(
        "/{}/{}?partNumber={}&uploadId={}",
        config.bucket, hash, part_number, upload_id
    );

    let mut req = Request::new(Method::PUT, format!("{}{}", config.endpoint(), path));
    req.set_header("Host", config.host());
    req.set_header("Content-Length", body.len().to_string());

    // Calculate content hash for this part
    let content_hash = hex::encode(Sha256::digest(body));
    sign_request(&mut req, &config, Some(content_hash))?;

    req.set_body(Body::from(body.to_vec()));

    let resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to upload part: {}", e)))?;

    if !resp.get_status().is_success() {
        return Err(BlossomError::StorageError(format!(
            "Upload part {} failed with status: {}",
            part_number,
            resp.get_status()
        )));
    }

    // Get ETag from response header
    let etag = resp
        .get_header("ETag")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.trim_matches('"').to_string())
        .ok_or_else(|| BlossomError::StorageError("Missing ETag in part response".into()))?;

    Ok(etag)
}
```

**Step 2: Build and verify**

Run:
```bash
cd /Users/rabble/code/divine/fastly-blossom-gcs && fastly compute build 2>&1
```
Expected: SUCCESS

**Step 3: Commit**

```bash
git add src/storage.rs
git commit -m "feat(storage): add upload_part for multipart uploads

- Upload individual parts with content hash signing
- Return ETag for completion manifest"
```

---

### Task 6: Add Complete Multipart Upload Function

**Files:**
- Modify: `src/storage.rs` (add after upload_part)

**Step 1: Add complete multipart function**

```rust
/// Complete a multipart upload
fn complete_multipart_upload(
    hash: &str,
    upload_id: &str,
    parts: &[(u32, String)], // (part_number, etag)
) -> Result<()> {
    let config = GCSConfig::load()?;
    let path = format!("/{}/{}?uploadId={}", config.bucket, hash, upload_id);

    // Build XML body
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (part_number, etag) in parts {
        xml.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>",
            part_number, etag
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");

    let content_hash = hex::encode(Sha256::digest(xml.as_bytes()));

    let mut req = Request::new(Method::POST, format!("{}{}", config.endpoint(), path));
    req.set_header("Host", config.host());
    req.set_header("Content-Type", "application/xml");
    req.set_header("Content-Length", xml.len().to_string());

    sign_request(&mut req, &config, Some(content_hash))?;

    req.set_body(xml);

    let resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to complete multipart: {}", e)))?;

    if !resp.get_status().is_success() {
        return Err(BlossomError::StorageError(format!(
            "Complete multipart failed with status: {}",
            resp.get_status()
        )));
    }

    Ok(())
}
```

**Step 2: Build and verify**

Run:
```bash
cd /Users/rabble/code/divine/fastly-blossom-gcs && fastly compute build 2>&1
```
Expected: SUCCESS

**Step 3: Commit**

```bash
git add src/storage.rs
git commit -m "feat(storage): add complete_multipart_upload

- Build XML manifest with part numbers and ETags
- Sign and send completion request"
```

---

### Task 7: Add Full Multipart Upload Orchestration

**Files:**
- Modify: `src/storage.rs` (add after complete_multipart_upload)

**Step 1: Add multipart orchestration function**

```rust
/// Upload a large blob using multipart upload
fn upload_blob_multipart(hash: &str, body: Body, content_type: &str, size: u64) -> Result<()> {
    // Read entire body into memory (required for chunking)
    let body_bytes = body.into_bytes();

    if body_bytes.len() as u64 != size {
        return Err(BlossomError::BadRequest(
            "Content-Length doesn't match body size".into(),
        ));
    }

    // Initiate multipart upload
    let upload_id = initiate_multipart_upload(hash, content_type)?;

    // Upload parts
    let mut parts: Vec<(u32, String)> = Vec::new();
    let mut offset: usize = 0;
    let mut part_number: u32 = 1;

    while offset < body_bytes.len() {
        let end = std::cmp::min(offset + PART_SIZE as usize, body_bytes.len());
        let chunk = &body_bytes[offset..end];

        let etag = upload_part(hash, &upload_id, part_number, chunk)?;
        parts.push((part_number, etag));

        offset = end;
        part_number += 1;
    }

    // Complete multipart upload
    complete_multipart_upload(hash, &upload_id, &parts)?;

    Ok(())
}
```

**Step 2: Build and verify**

Run:
```bash
cd /Users/rabble/code/divine/fastly-blossom-gcs && fastly compute build 2>&1
```
Expected: SUCCESS with no warnings about unused functions

**Step 3: Commit**

```bash
git add src/storage.rs
git commit -m "feat(storage): add upload_blob_multipart orchestration

- Chunk body into PART_SIZE pieces
- Coordinate initiate, upload parts, complete flow
- Called automatically for files > MULTIPART_THRESHOLD"
```

---

## Phase 3: Configuration Updates

### Task 8: Update fastly.toml.example for GCS

**Files:**
- Modify: `fastly.toml.example`

**Step 1: Update example config with GCS settings**

```toml
# ABOUTME: Example Fastly Compute service configuration
# ABOUTME: Copy to fastly.toml and fill in your credentials

manifest_version = 3
name = "fastly-blossom"
description = "Blossom media server for Nostr"
authors = ["Divine <hello@divine.video>"]
language = "rust"

[local_server]

  [local_server.backends]

    [local_server.backends.gcs_storage]
    url = "https://storage.googleapis.com"

  [local_server.kv_stores]

    [local_server.kv_stores.blossom_metadata]
    file = "kv-store-data.json"

  [local_server.config_stores]

    [local_server.config_stores.blossom_config]

      [local_server.config_stores.blossom_config.contents]
      gcs_bucket = "YOUR_BUCKET_NAME"

  [local_server.secret_stores]

    [local_server.secret_stores.blossom_secrets]

      [local_server.secret_stores.blossom_secrets.contents]

        [local_server.secret_stores.blossom_secrets.contents.gcs_access_key]
        plaintext = "YOUR_GCS_HMAC_ACCESS_KEY"

        [local_server.secret_stores.blossom_secrets.contents.gcs_secret_key]
        plaintext = "YOUR_GCS_HMAC_SECRET_KEY"

[setup]

  [setup.backends]

    [setup.backends.gcs_storage]
    description = "Google Cloud Storage S3-compatible API"
    address = "storage.googleapis.com"
    port = 443

  [setup.kv_stores]

    [setup.kv_stores.blossom_metadata]
    description = "Blob metadata storage"

  [setup.config_stores]

    [setup.config_stores.blossom_config]
    description = "Service configuration"
    items = [
      { key = "gcs_bucket", description = "GCS bucket name" },
    ]

  [setup.secret_stores]

    [setup.secret_stores.blossom_secrets]
    description = "Sensitive credentials"
    entries = [
      { key = "gcs_access_key", description = "GCS HMAC access key" },
      { key = "gcs_secret_key", description = "GCS HMAC secret key" },
    ]
```

**Step 2: Commit**

```bash
git add fastly.toml.example
git commit -m "docs(config): update fastly.toml.example for GCS

- Change backend from b2_storage to gcs_storage
- Update config keys: gcs_bucket
- Update secret keys: gcs_access_key, gcs_secret_key
- Point to storage.googleapis.com"
```

---

### Task 9: Create GCS Setup Script

**Files:**
- Create: `scripts/setup-gcs.sh`

**Step 1: Create setup helper script**

```bash
#!/bin/bash
# ABOUTME: Helper script to set up GCS bucket and HMAC keys
# ABOUTME: Run this to prepare GCS infrastructure for Blossom

set -e

PROJECT_ID="${GCP_PROJECT_ID:-}"
BUCKET_NAME="${GCS_BUCKET_NAME:-blossom-media}"
LOCATION="${GCS_LOCATION:-us-central1}"
SERVICE_ACCOUNT="${GCS_SERVICE_ACCOUNT:-}"

if [ -z "$PROJECT_ID" ]; then
    echo "Error: GCP_PROJECT_ID environment variable required"
    exit 1
fi

echo "Setting up GCS for Blossom..."
echo "Project: $PROJECT_ID"
echo "Bucket: $BUCKET_NAME"
echo "Location: $LOCATION"

# Create bucket
echo ""
echo "Step 1: Creating bucket..."
gsutil mb -p "$PROJECT_ID" -l "$LOCATION" "gs://$BUCKET_NAME" 2>/dev/null || echo "Bucket may already exist"

# Enable uniform bucket-level access
echo ""
echo "Step 2: Enabling uniform bucket-level access..."
gsutil uniformbucketlevelaccess set on "gs://$BUCKET_NAME"

# Create HMAC keys (if service account provided)
if [ -n "$SERVICE_ACCOUNT" ]; then
    echo ""
    echo "Step 3: Creating HMAC keys for $SERVICE_ACCOUNT..."
    gsutil hmac create "$SERVICE_ACCOUNT"
    echo ""
    echo "IMPORTANT: Save the access_id and secret above!"
    echo "Add them to your fastly.toml as gcs_access_key and gcs_secret_key"
else
    echo ""
    echo "Step 3: Skipping HMAC key creation (no SERVICE_ACCOUNT provided)"
    echo "To create HMAC keys later:"
    echo "  gsutil hmac create SERVICE_ACCOUNT_EMAIL"
fi

echo ""
echo "GCS setup complete!"
echo ""
echo "Next steps:"
echo "1. Copy fastly.toml.example to fastly.toml"
echo "2. Fill in gcs_bucket, gcs_access_key, gcs_secret_key"
echo "3. Set up Cloud Function for content moderation (see docs/plans/2025-12-03-gcs-migration-design.md)"
```

**Step 2: Make executable and commit**

```bash
chmod +x scripts/setup-gcs.sh
git add scripts/setup-gcs.sh
git commit -m "feat(scripts): add GCS setup helper script

- Creates bucket with uniform access
- Creates HMAC keys for service account
- Provides next steps for configuration"
```

---

## Phase 4: Metadata Updates

### Task 10: Add Thumbnail and Moderation Fields to BlobMetadata

**Files:**
- Modify: `src/blossom.rs:24-57`

**Step 1: Add new fields to BlobMetadata struct**

```rust
/// Blob metadata stored in KV store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMetadata {
    /// SHA-256 hash (hex encoded)
    pub sha256: String,
    /// Size in bytes
    pub size: u64,
    /// MIME type
    #[serde(rename = "type")]
    pub mime_type: String,
    /// Upload timestamp (ISO 8601)
    pub uploaded: String,
    /// Owner's nostr public key (hex encoded)
    pub owner: String,
    /// Content status for moderation
    pub status: BlobStatus,
    /// Path to thumbnail (for videos)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<String>,
    /// Moderation check results
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moderation: Option<ModerationResult>,
}

/// Content moderation result from Cloud Function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModerationResult {
    /// When the check was performed (ISO 8601)
    pub checked_at: String,
    /// Whether content passed safety checks
    pub is_safe: bool,
    /// SafeSearch likelihood scores (optional detail)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scores: Option<SafetyScores>,
}

/// SafeSearch likelihood scores
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyScores {
    pub adult: String,
    pub violence: String,
    pub racy: String,
}
```

**Step 2: Build and verify**

Run:
```bash
cd /Users/rabble/code/divine/fastly-blossom-gcs && fastly compute build 2>&1
```
Expected: SUCCESS

**Step 3: Commit**

```bash
git add src/blossom.rs
git commit -m "feat(blossom): add thumbnail and moderation fields

- Add thumbnail field for video blob thumbnail paths
- Add ModerationResult struct with checked_at, is_safe
- Add SafetyScores for Vision API likelihood values"
```

---

### Task 11: Update main.rs to Initialize New Metadata Fields

**Files:**
- Modify: `src/main.rs:195-202`

**Step 1: Update metadata creation in handle_upload**

```rust
    // Store metadata
    let metadata = BlobMetadata {
        sha256: hash.clone(),
        size: actual_size,
        mime_type: content_type,
        uploaded: current_timestamp(),
        owner: auth.pubkey.clone(),
        status: BlobStatus::Pending, // Start as pending for moderation
        thumbnail: None,             // Set by Cloud Function for videos
        moderation: None,            // Set by Cloud Function after check
    };
```

**Step 2: Build and verify**

Run:
```bash
cd /Users/rabble/code/divine/fastly-blossom-gcs && fastly compute build 2>&1
```
Expected: SUCCESS

**Step 3: Commit**

```bash
git add src/main.rs
git commit -m "feat(main): initialize thumbnail and moderation fields

- Set thumbnail to None on upload (Cloud Function populates)
- Set moderation to None on upload (Cloud Function populates)"
```

---

## Phase 5: Cloud Function (Python)

### Task 12: Create Cloud Function Directory Structure

**Files:**
- Create: `cloud-functions/process-blob/main.py`
- Create: `cloud-functions/process-blob/requirements.txt`

**Step 1: Create requirements.txt**

```txt
functions-framework==3.*
google-cloud-storage==2.*
google-cloud-vision==3.*
google-cloud-videointelligence==2.*
requests==2.*
```

**Step 2: Create main.py**

```python
# ABOUTME: Cloud Function triggered by GCS object finalize events
# ABOUTME: Performs content moderation and video thumbnail extraction

import os
import json
import requests
from datetime import datetime
from google.cloud import storage
from google.cloud import vision
from google.cloud.vision_v1 import types

# Fastly KV API endpoint for metadata updates
# This would be a webhook endpoint on your Fastly service
METADATA_WEBHOOK_URL = os.environ.get('METADATA_WEBHOOK_URL', '')
METADATA_WEBHOOK_SECRET = os.environ.get('METADATA_WEBHOOK_SECRET', '')


def process_blob(event, context):
    """
    Triggered by a new object in GCS bucket.

    Args:
        event: GCS event data
        context: Cloud Function context
    """
    bucket_name = event['bucket']
    blob_name = event['name']
    content_type = event.get('contentType', 'application/octet-stream')

    print(f"Processing: gs://{bucket_name}/{blob_name} ({content_type})")

    # Skip thumbnails (they're our output, not input)
    if blob_name.startswith('thumbnails/'):
        print("Skipping thumbnail")
        return

    # Process based on content type
    if content_type.startswith('image/'):
        result = check_image_safety(bucket_name, blob_name)
        handle_moderation_result(bucket_name, blob_name, result)

    elif content_type.startswith('video/'):
        # For videos: extract thumbnail, then check thumbnail
        thumbnail_path = extract_video_thumbnail(bucket_name, blob_name)
        if thumbnail_path:
            result = check_image_safety(bucket_name, thumbnail_path)
            handle_moderation_result(bucket_name, blob_name, result, thumbnail_path)
        else:
            # Thumbnail extraction failed, mark as pending review
            update_metadata(blob_name, 'pending', None, None)
    else:
        # Non-image/video content, auto-approve
        update_metadata(blob_name, 'active', None, create_moderation_result(True))


def check_image_safety(bucket_name: str, blob_name: str) -> dict:
    """
    Check image safety using Vision API SafeSearch.

    Returns:
        dict with is_flagged, reason, scores
    """
    client = vision.ImageAnnotatorClient()

    image = types.Image(
        source=types.ImageSource(
            gcs_image_uri=f'gs://{bucket_name}/{blob_name}'
        )
    )

    response = client.safe_search_detection(image=image)
    safe = response.safe_search_annotation

    # Get likelihood values
    likelihood_name = vision.Likelihood

    # Flag if LIKELY or VERY_LIKELY for adult or violence
    is_flagged = (
        safe.adult >= likelihood_name.LIKELY or
        safe.violence >= likelihood_name.LIKELY
    )

    scores = {
        'adult': likelihood_name(safe.adult).name,
        'violence': likelihood_name(safe.violence).name,
        'racy': likelihood_name(safe.racy).name,
    }

    reason = None
    if is_flagged:
        reasons = []
        if safe.adult >= likelihood_name.LIKELY:
            reasons.append(f"adult:{scores['adult']}")
        if safe.violence >= likelihood_name.LIKELY:
            reasons.append(f"violence:{scores['violence']}")
        reason = ", ".join(reasons)

    return {
        'is_flagged': is_flagged,
        'reason': reason,
        'scores': scores
    }


def extract_video_thumbnail(bucket_name: str, blob_name: str) -> str:
    """
    Extract a thumbnail frame from video.
    For now, uses first frame via simple ffmpeg or Cloud Video Intelligence.

    Returns:
        Path to uploaded thumbnail, or None if failed
    """
    # Simple approach: download video, extract frame with ffprobe/ffmpeg
    # For production, consider Cloud Video Intelligence API

    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)

    # For MVP: just copy first frame as thumbnail
    # This is a placeholder - real implementation would use ffmpeg or Video Intelligence
    thumbnail_path = f'thumbnails/{blob_name}'

    # TODO: Implement actual thumbnail extraction
    # Option 1: Cloud Run with ffmpeg
    # Option 2: Video Intelligence API shot detection

    print(f"TODO: Extract thumbnail to {thumbnail_path}")
    return None  # Return None until implemented


def handle_moderation_result(bucket_name: str, blob_name: str, result: dict, thumbnail_path: str = None):
    """Handle the moderation result - delete if flagged, update metadata."""
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)

    if result['is_flagged']:
        print(f"Content flagged: {result['reason']}")

        # Delete the blob
        blob = bucket.blob(blob_name)
        blob.delete()
        print(f"Deleted: {blob_name}")

        # Delete thumbnail if exists
        if thumbnail_path:
            thumb_blob = bucket.blob(thumbnail_path)
            try:
                thumb_blob.delete()
                print(f"Deleted thumbnail: {thumbnail_path}")
            except Exception:
                pass

        # Update metadata to restricted/deleted
        update_metadata(blob_name, 'restricted', thumbnail_path,
                       create_moderation_result(False, result['scores']))
    else:
        # Content is safe
        update_metadata(blob_name, 'active', thumbnail_path,
                       create_moderation_result(True, result['scores']))


def create_moderation_result(is_safe: bool, scores: dict = None) -> dict:
    """Create a moderation result object."""
    result = {
        'checked_at': datetime.utcnow().isoformat() + 'Z',
        'is_safe': is_safe
    }
    if scores:
        result['scores'] = scores
    return result


def update_metadata(blob_name: str, status: str, thumbnail: str, moderation: dict):
    """
    Update blob metadata in Fastly KV store via webhook.

    In production, this calls a secure webhook endpoint on your Fastly service
    that updates the KV store metadata.
    """
    if not METADATA_WEBHOOK_URL:
        print(f"METADATA_WEBHOOK_URL not set, skipping update for {blob_name}")
        print(f"  status={status}, thumbnail={thumbnail}, moderation={moderation}")
        return

    payload = {
        'sha256': blob_name,
        'status': status,
        'thumbnail': thumbnail,
        'moderation': moderation
    }

    headers = {
        'Content-Type': 'application/json',
        'X-Webhook-Secret': METADATA_WEBHOOK_SECRET
    }

    try:
        response = requests.post(METADATA_WEBHOOK_URL, json=payload, headers=headers)
        response.raise_for_status()
        print(f"Updated metadata for {blob_name}")
    except Exception as e:
        print(f"Failed to update metadata: {e}")
```

**Step 3: Commit**

```bash
git add cloud-functions/
git commit -m "feat(cloud-function): add content moderation Cloud Function

- GCS object finalize trigger
- Vision API SafeSearch for image/video moderation
- Placeholder for video thumbnail extraction
- Webhook-based metadata update to Fastly KV"
```

---

### Task 13: Create Cloud Function Deployment Script

**Files:**
- Create: `scripts/deploy-cloud-function.sh`

**Step 1: Create deployment script**

```bash
#!/bin/bash
# ABOUTME: Deploy the content moderation Cloud Function
# ABOUTME: Requires gcloud CLI authenticated and configured

set -e

PROJECT_ID="${GCP_PROJECT_ID:-}"
BUCKET_NAME="${GCS_BUCKET_NAME:-blossom-media}"
REGION="${GCS_REGION:-us-central1}"
FUNCTION_NAME="process-blob"

if [ -z "$PROJECT_ID" ]; then
    echo "Error: GCP_PROJECT_ID environment variable required"
    exit 1
fi

echo "Deploying Cloud Function..."
echo "Project: $PROJECT_ID"
echo "Bucket: $BUCKET_NAME"
echo "Region: $REGION"

cd "$(dirname "$0")/../cloud-functions/process-blob"

gcloud functions deploy "$FUNCTION_NAME" \
    --project="$PROJECT_ID" \
    --region="$REGION" \
    --runtime=python311 \
    --trigger-resource="$BUCKET_NAME" \
    --trigger-event=google.storage.object.finalize \
    --entry-point=process_blob \
    --memory=512MB \
    --timeout=120s \
    --set-env-vars="METADATA_WEBHOOK_URL=${METADATA_WEBHOOK_URL:-},METADATA_WEBHOOK_SECRET=${METADATA_WEBHOOK_SECRET:-}"

echo ""
echo "Cloud Function deployed!"
echo "View logs: gcloud functions logs read $FUNCTION_NAME --region=$REGION"
```

**Step 2: Make executable and commit**

```bash
chmod +x scripts/deploy-cloud-function.sh
git add scripts/deploy-cloud-function.sh
git commit -m "feat(scripts): add Cloud Function deployment script

- Deploys process-blob function to specified region
- Configures GCS object finalize trigger
- Sets environment variables for webhook"
```

---

## Phase 6: Integration Testing

### Task 14: Create Integration Test Script

**Files:**
- Create: `scripts/test-gcs-integration.sh`

**Step 1: Create test script**

```bash
#!/bin/bash
# ABOUTME: Integration test for GCS storage operations
# ABOUTME: Tests upload, download, and delete via local Viceroy server

set -e

BASE_URL="${BASE_URL:-http://127.0.0.1:7676}"

echo "Testing GCS integration..."
echo "Base URL: $BASE_URL"

# Check version endpoint
echo ""
echo "1. Testing version endpoint..."
VERSION=$(curl -s "$BASE_URL/version")
echo "Version: $VERSION"

# Create test file
echo ""
echo "2. Creating test file..."
TEST_CONTENT="Hello GCS $(date +%s)"
echo "$TEST_CONTENT" > /tmp/test-gcs.txt
EXPECTED_HASH=$(shasum -a 256 /tmp/test-gcs.txt | cut -d' ' -f1)
echo "Expected SHA256: $EXPECTED_HASH"

# Note: Full upload test requires valid Nostr auth
# This is a placeholder for manual testing
echo ""
echo "3. Upload test requires Nostr auth token"
echo "   Use test-upload.mjs for authenticated upload tests"

# Test HEAD for non-existent blob
echo ""
echo "4. Testing HEAD for non-existent blob..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/$EXPECTED_HASH")
echo "HTTP Code: $HTTP_CODE (expected 404)"

if [ "$HTTP_CODE" != "404" ]; then
    echo "WARNING: Expected 404, got $HTTP_CODE"
fi

echo ""
echo "Basic integration tests complete!"
echo ""
echo "For full testing:"
echo "1. Set up GCS credentials in fastly.toml"
echo "2. Run: fastly compute serve"
echo "3. Run: node test-upload.mjs"
```

**Step 2: Make executable and commit**

```bash
chmod +x scripts/test-gcs-integration.sh
git add scripts/test-gcs-integration.sh
git commit -m "feat(scripts): add GCS integration test script

- Basic connectivity tests
- Version endpoint check
- HEAD request for non-existent blob
- Instructions for full authenticated testing"
```

---

### Task 15: Final Build and Verification

**Files:**
- All modified files

**Step 1: Full rebuild**

Run:
```bash
cd /Users/rabble/code/divine/fastly-blossom-gcs && fastly compute build 2>&1
```
Expected: SUCCESS with no errors

**Step 2: Verify file structure**

Run:
```bash
ls -la /Users/rabble/code/divine/fastly-blossom-gcs/
ls -la /Users/rabble/code/divine/fastly-blossom-gcs/src/
ls -la /Users/rabble/code/divine/fastly-blossom-gcs/scripts/
ls -la /Users/rabble/code/divine/fastly-blossom-gcs/cloud-functions/
```

**Step 3: Create summary commit**

```bash
git add -A
git status
# If there are any uncommitted changes:
git commit -m "chore: finalize GCS migration implementation

Complete migration from B2 to GCS:
- GCS HMAC authentication via S3-compat API
- Multipart upload for files > 5MB
- Updated configuration templates
- Cloud Function for content moderation
- Integration test scripts"
```

---

## Summary

This plan migrates Fastly Blossom from Backblaze B2 to Google Cloud Storage:

| Component | Changes |
|-----------|---------|
| `src/storage.rs` | GCS HMAC config, multipart uploads |
| `src/blossom.rs` | Thumbnail + moderation metadata fields |
| `src/main.rs` | Initialize new metadata fields |
| `fastly.toml.example` | GCS backend and credentials |
| `cloud-functions/` | Python Cloud Function for moderation |
| `scripts/` | Setup and deployment helpers |

**After implementation:**
1. Set up GCS bucket with `scripts/setup-gcs.sh`
2. Update `fastly.toml` with GCS credentials
3. Deploy Cloud Function with `scripts/deploy-cloud-function.sh`
4. Test locally with `fastly compute serve`
5. Deploy to Fastly with `fastly compute deploy`
