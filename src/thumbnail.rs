// ABOUTME: Video thumbnail extraction stub
// ABOUTME: FFmpeg-WASI works in Viceroy but fails on Fastly production

use crate::error::{BlossomError, Result};

/// Result of thumbnail extraction
pub struct ThumbnailResult {
    pub width: u32,
    pub height: u32,
    pub rgb_data: Vec<u8>,
}

/// Extract a thumbnail from video data
///
/// Note: This feature is currently disabled in production because
/// ffmpeg-wasi fails to load on Fastly's production WASM runtime
/// despite working correctly in Viceroy (local development).
pub fn extract_thumbnail(_video_data: &[u8]) -> Result<ThumbnailResult> {
    Err(BlossomError::Internal(
        "Thumbnail extraction is temporarily unavailable (ffmpeg-wasi incompatible with Fastly production)".into(),
    ))
}

/// Encode RGB data to simple PPM format (for debugging/testing)
pub fn rgb_to_ppm(result: &ThumbnailResult) -> Vec<u8> {
    let header = format!("P6\n{} {}\n255\n", result.width, result.height);
    let mut ppm = Vec::with_capacity(header.len() + result.rgb_data.len());
    ppm.extend_from_slice(header.as_bytes());
    ppm.extend_from_slice(&result.rgb_data);
    ppm
}
