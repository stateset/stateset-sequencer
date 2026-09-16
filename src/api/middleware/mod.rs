//! Reusable API middleware layers.

pub mod deprecation;
pub mod payment_required;

pub use deprecation::{
    is_legacy_v1_path, v1_deprecation_middleware, V1_SUCCESSOR_LINK, V1_SUNSET_HTTP_DATE,
};
pub use payment_required::{
    payment_required_middleware, PaymentRequiredConfig, PaymentRequiredState, X_PAYMENT_HEADER,
    X_PAYMENT_RECEIPT_HEADER,
};
