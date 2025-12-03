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

/// Get config value
fn get_config(key: &str) -> Result<String> {
    let store = fastly::config_store::ConfigStore::open(CONFIG_STORE);
    store
        .get(key)
        .ok_or_else(|| BlossomError::Internal(format!("Missing config: {}", key)))
}

/// Get secret value
fn get_secret(key: &str) -> Result<String> {
    let store = fastly::secret_store::SecretStore::open(SECRET_STORE)
        .map_err(|e| BlossomError::Internal(format!("Failed to open secret store: {}", e)))?;

    let secret = store
        .get(key)
        .ok_or_else(|| BlossomError::Internal(format!("Missing secret: {}", key)))?;

    // Convert Bytes to String
    let plaintext_bytes = secret.plaintext();
    String::from_utf8(plaintext_bytes.to_vec())
        .map_err(|e| BlossomError::Internal(format!("Secret is not valid UTF-8: {}", e)))
}

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

/// Get current time as ISO 8601 string
pub fn current_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = now.as_secs();

    // Convert to date/time components (simplified UTC calculation)
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate year, month, day from days since epoch (Jan 1, 1970)
    let (year, month, day) = days_to_ymd(days_since_epoch);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to year, month, day
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Simplified calculation - good enough for our purposes
    let mut remaining_days = days as i64;
    let mut year = 1970i64;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months: [i64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1i64;
    for &days_in_month in &days_in_months {
        if remaining_days < days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    let day = remaining_days + 1;

    (year as u64, month as u64, day as u64)
}

/// Check if a year is a leap year
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

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

/// Generate AWS v4 signing key
fn get_signing_key(secret_key: &str, date_stamp: &str, region: &str) -> Result<Vec<u8>> {
    let k_date = hmac_sha256(format!("AWS4{}", secret_key).as_bytes(), date_stamp.as_bytes())?;
    let k_region = hmac_sha256(&k_date, region.as_bytes())?;
    let k_service = hmac_sha256(&k_region, SERVICE.as_bytes())?;
    let k_signing = hmac_sha256(&k_service, b"aws4_request")?;
    Ok(k_signing)
}

/// HMAC-SHA256
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| BlossomError::Internal(format!("HMAC error: {}", e)))?;

    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Placeholder for body hash during signing
/// For streaming uploads, we use UNSIGNED-PAYLOAD
fn hash_body_for_signing(_size: u64) -> String {
    // For large uploads, use unsigned payload and let GCS verify
    "UNSIGNED-PAYLOAD".into()
}
