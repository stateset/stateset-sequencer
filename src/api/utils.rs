//! Utility functions for REST API handlers.
//!
//! Common utilities for request/response handling, validation, and encoding.

use axum::http::StatusCode;
use base64::Engine;

/// Decode base64 with flexible format support (standard, URL-safe, with/without padding).
///
/// Tries multiple base64 encodings in order:
/// 1. Standard with padding (RFC 4648)
/// 2. Standard without padding
/// 3. URL-safe with padding
/// 4. URL-safe without padding
///
/// This allows clients to use any common base64 encoding format.
pub fn decode_base64_any(s: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    let trimmed = s.trim();
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_base64_standard_with_padding() {
        let original = b"hello world";
        let encoded = base64::engine::general_purpose::STANDARD.encode(original);
        let decoded = decode_base64_any(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_decode_base64_standard_no_padding() {
        let original = b"hello world";
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(original);
        let decoded = decode_base64_any(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_decode_base64_url_safe() {
        let original = b"hello world";
        let encoded = base64::engine::general_purpose::URL_SAFE.encode(original);
        let decoded = decode_base64_any(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_decode_base64_url_safe_no_padding() {
        let original = b"hello world";
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(original);
        let decoded = decode_base64_any(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_decode_base64_with_whitespace() {
        let original = b"hello world";
        let encoded = format!("  {}  ", base64::engine::general_purpose::STANDARD.encode(original));
        let decoded = decode_base64_any(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_decode_base64_invalid() {
        let result = decode_base64_any("not valid base64!!!");
        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_decode_base64_binary_data() {
        // Test with binary data that produces URL-unsafe characters
        let original: Vec<u8> = (0..255).collect();
        let encoded = base64::engine::general_purpose::URL_SAFE.encode(&original);
        let decoded = decode_base64_any(&encoded).unwrap();
        assert_eq!(decoded, original);
    }
}
