# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Cloud Run upload service for handling large file uploads (>500KB)
  - Rust-based service with Nostr auth validation
  - Streaming upload to GCS with SHA-256 hashing
  - HTTP/2 support to bypass Fastly 32MB body size limit
- Fastly proxy to Cloud Run for large uploads
  - Files <500KB handled in-process via AWS v4 signed GCS uploads
  - Files >500KB proxied to Cloud Run service
- Migration scripts for blob data migration
  - Bucket-to-bucket copy script using HMAC/S3 API for GCS
- Cloud Functions for content moderation (process-blob)
- BUD-04 mirroring with automatic blob retrieval from fallback CDNs
- BUD-06 pre-upload validation support
- CDN fallback chain (cdn.divine.video, blossom.divine.video, cdn.satellite.earth, image.nostr.build)

### Changed
- Fastly Compute now routes large uploads to Cloud Run instead of streaming in-process
  - Fixes WASM memory OOM issues with large files
- Updated .gitignore to exclude Rust target directories in subdirectories
- Switched from staging to production GCS bucket (divine-blossom-media)

### Fixed
- WASM out-of-memory errors when uploading files >5MB
- Production GCS bucket IAM permissions for public read access and Cloud Run uploads
