//! Utility functions for REST API handlers.

use axum::http::StatusCode;
use base64::Engine;

/// Decode base64 with flexible format support (standard, URL-safe, with/without padding).
pub fn decode_base64_any(s: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    let trimmed = s.trim();
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid base64: {e}")))
}
