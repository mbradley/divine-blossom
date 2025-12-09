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
- Cloud Functions for content moderation (process-blob)

### Changed
- Fastly Compute now routes large uploads to Cloud Run instead of streaming in-process
  - Fixes WASM memory OOM issues with large files
- Updated .gitignore to exclude Rust target directories in subdirectories

### Fixed
- WASM out-of-memory errors when uploading files >5MB
