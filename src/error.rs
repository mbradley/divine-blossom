// ABOUTME: Error types for the Blossom server
// ABOUTME: Provides unified error handling with HTTP status code mapping

use fastly::http::StatusCode;
use std::fmt;

/// Unified error type for the Blossom server
#[derive(Debug)]
pub enum BlossomError {
    /// Authentication failed or missing
    AuthRequired(String),
    /// Authentication provided but invalid
    AuthInvalid(String),
    /// Forbidden - authenticated but not authorized
    Forbidden(String),
    /// Blob not found
    NotFound(String),
    /// Bad request - malformed input
    BadRequest(String),
    /// Storage backend error
    StorageError(String),
    /// Metadata store error
    MetadataError(String),
    /// Internal server error
    Internal(String),
}

impl BlossomError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            BlossomError::AuthRequired(_) => StatusCode::UNAUTHORIZED,
            BlossomError::AuthInvalid(_) => StatusCode::UNAUTHORIZED,
            BlossomError::Forbidden(_) => StatusCode::FORBIDDEN,
            BlossomError::NotFound(_) => StatusCode::NOT_FOUND,
            BlossomError::BadRequest(_) => StatusCode::BAD_REQUEST,
            BlossomError::StorageError(_) => StatusCode::BAD_GATEWAY,
            BlossomError::MetadataError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            BlossomError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get the error message
    pub fn message(&self) -> &str {
        match self {
            BlossomError::AuthRequired(msg) => msg,
            BlossomError::AuthInvalid(msg) => msg,
            BlossomError::Forbidden(msg) => msg,
            BlossomError::NotFound(msg) => msg,
            BlossomError::BadRequest(msg) => msg,
            BlossomError::StorageError(msg) => msg,
            BlossomError::MetadataError(msg) => msg,
            BlossomError::Internal(msg) => msg,
        }
    }
}

impl fmt::Display for BlossomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for BlossomError {}

/// Result type alias for Blossom operations
pub type Result<T> = std::result::Result<T, BlossomError>;
