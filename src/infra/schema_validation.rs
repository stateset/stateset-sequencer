//! Schema validation configuration for event ingestion.
//!
//! This module provides configurable schema validation behavior:
//! - Disabled: No schema validation performed
//! - WarnOnly: Validate and log warnings, but accept events
//! - Enforce: Validate against schemas when they exist, allow events without schemas
//! - Required: Require schemas for all events, reject those without registered schemas

use std::fmt;

/// Schema validation mode for event ingestion
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SchemaValidationMode {
    /// No schema validation performed
    Disabled,
    /// Validate and log warnings, but accept all events
    WarnOnly,
    /// Validate against schemas when they exist, allow events without schemas
    #[default]
    Enforce,
    /// Require schemas for all events, reject those without registered schemas
    Required,
}

impl SchemaValidationMode {
    /// Parse from environment variable value
    pub fn from_env_value(value: &str) -> Result<Self, String> {
        match value.trim().to_lowercase().as_str() {
            "disabled" | "off" | "none" | "false" | "0" => Ok(Self::Disabled),
            "warn" | "warnonly" | "warn_only" | "warning" => Ok(Self::WarnOnly),
            "enforce" | "on" | "true" | "1" | "" => Ok(Self::Enforce),
            "required" | "strict" | "require" => Ok(Self::Required),
            other => Err(format!(
                "Invalid schema validation mode: '{}'. Expected: disabled, warn, enforce, or required",
                other
            )),
        }
    }

    /// Load from environment variable SCHEMA_VALIDATION_MODE
    pub fn from_env() -> Self {
        match std::env::var("SCHEMA_VALIDATION_MODE") {
            Ok(value) => Self::from_env_value(&value).unwrap_or_else(|e| {
                tracing::warn!("{}", e);
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    /// Check if validation should be performed
    pub fn should_validate(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Check if validation failures should reject events
    pub fn should_reject_on_failure(&self) -> bool {
        matches!(self, Self::Enforce | Self::Required)
    }

    /// Check if missing schemas should reject events
    pub fn should_reject_missing_schema(&self) -> bool {
        matches!(self, Self::Required)
    }
}

impl fmt::Display for SchemaValidationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "disabled"),
            Self::WarnOnly => write!(f, "warn_only"),
            Self::Enforce => write!(f, "enforce"),
            Self::Required => write!(f, "required"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_disabled() {
        assert_eq!(
            SchemaValidationMode::from_env_value("disabled").unwrap(),
            SchemaValidationMode::Disabled
        );
        assert_eq!(
            SchemaValidationMode::from_env_value("off").unwrap(),
            SchemaValidationMode::Disabled
        );
        assert_eq!(
            SchemaValidationMode::from_env_value("0").unwrap(),
            SchemaValidationMode::Disabled
        );
    }

    #[test]
    fn test_parse_warn_only() {
        assert_eq!(
            SchemaValidationMode::from_env_value("warn").unwrap(),
            SchemaValidationMode::WarnOnly
        );
        assert_eq!(
            SchemaValidationMode::from_env_value("warnonly").unwrap(),
            SchemaValidationMode::WarnOnly
        );
    }

    #[test]
    fn test_parse_enforce() {
        assert_eq!(
            SchemaValidationMode::from_env_value("enforce").unwrap(),
            SchemaValidationMode::Enforce
        );
        assert_eq!(
            SchemaValidationMode::from_env_value("on").unwrap(),
            SchemaValidationMode::Enforce
        );
        assert_eq!(
            SchemaValidationMode::from_env_value("1").unwrap(),
            SchemaValidationMode::Enforce
        );
    }

    #[test]
    fn test_parse_required() {
        assert_eq!(
            SchemaValidationMode::from_env_value("required").unwrap(),
            SchemaValidationMode::Required
        );
        assert_eq!(
            SchemaValidationMode::from_env_value("strict").unwrap(),
            SchemaValidationMode::Required
        );
    }

    #[test]
    fn test_parse_invalid() {
        assert!(SchemaValidationMode::from_env_value("invalid").is_err());
    }

    #[test]
    fn test_should_validate() {
        assert!(!SchemaValidationMode::Disabled.should_validate());
        assert!(SchemaValidationMode::WarnOnly.should_validate());
        assert!(SchemaValidationMode::Enforce.should_validate());
        assert!(SchemaValidationMode::Required.should_validate());
    }

    #[test]
    fn test_should_reject_on_failure() {
        assert!(!SchemaValidationMode::Disabled.should_reject_on_failure());
        assert!(!SchemaValidationMode::WarnOnly.should_reject_on_failure());
        assert!(SchemaValidationMode::Enforce.should_reject_on_failure());
        assert!(SchemaValidationMode::Required.should_reject_on_failure());
    }

    #[test]
    fn test_should_reject_missing_schema() {
        assert!(!SchemaValidationMode::Disabled.should_reject_missing_schema());
        assert!(!SchemaValidationMode::WarnOnly.should_reject_missing_schema());
        assert!(!SchemaValidationMode::Enforce.should_reject_missing_schema());
        assert!(SchemaValidationMode::Required.should_reject_missing_schema());
    }
}
