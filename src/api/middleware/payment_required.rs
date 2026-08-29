//! HTTP 402 Payment Required middleware (x402 challenge/response flow).
//!
//! Gates a route behind an x402 micropayment:
//!
//! ```text
//! 1. GET <paid resource>
//!        -> 402 Payment Required
//!           body: structured ApiError (code PAYMENT_REQUIRED) whose `details`
//!           carry the JSON payment requirements
//!           { x402_version, asset, network, chain_id, amount, pay_to,
//!             resource, max_validity_secs, ... }
//!
//! 2. Agent signs an X402PaymentIntent (Ed25519 over the X402_PAYMENT_V1
//!    domain-separated SHA-256 signing hash — see
//!    PgX402Repository::compute_signing_hash and cli/src/x402/client.js)
//!
//! 3. GET <paid resource>
//!        X-Payment: base64(JSON SubmitX402PaymentRequest)
//!        -> 200 OK
//!           X-Payment-Receipt: base64(JSON X402PaymentReceiptHeader)
//! ```
//!
//! # Wire format
//!
//! The `X-Payment` header carries the standard-base64 encoding of the exact
//! JSON document that `POST /api/v1/x402/payments` accepts
//! ([`SubmitX402PaymentRequest`], snake_case fields — the same shape produced
//! by `cli/src/x402/client.js`). Base64 is used because raw JSON is not safe
//! in HTTP header values; this mirrors the x402 protocol convention of
//! base64-encoded JSON payment payloads.
//!
//! Verified intents are persisted through the exact same code path as the
//! submission endpoint ([`verify_and_sequence_payment`]), so they receive a
//! sequence number, burn their nonce (replay protection via the
//! `x402_nonce_tracking` table's primary-key reservation), and enter the
//! normal batching/settlement pipeline. The `X-Payment-Receipt` response
//! header acknowledges sequencing and points at the full Merkle receipt
//! endpoint (`/api/v1/x402/payments/:intent_id/receipt`), which becomes
//! available once the intent is batched.
//!
//! # Replay protection
//!
//! A signed intent presented via `X-Payment` is *consumed* by the request it
//! pays for: any `idempotency_key` in the decoded intent is discarded (it is
//! not part of the signed hash) so a replay cannot short-circuit through the
//! idempotency lookup, and the nonce reservation makes the second
//! presentation fail with the same "Nonce already used for this payer" error
//! the submission endpoint returns.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use tracing::{debug, info, warn};

use crate::api::error::{ApiError, ErrorCode};
use crate::api::handlers::x402::verify_and_sequence_payment;
use crate::auth::AuthContextExt;
use crate::domain::{
    SubmitX402PaymentRequest, X402Asset, X402Network, X402PaymentReceiptHeader,
    X402PaymentRequirements, X402_MAX_VALIDITY_SECS, X402_VERSION,
};
use crate::infra::{PgAgentKeyRegistry, PgX402Repository};

/// Request header carrying the signed payment intent (base64 JSON).
pub const X_PAYMENT_HEADER: &str = "x-payment";

/// Response header carrying the payment receipt (base64 JSON).
pub const X_PAYMENT_RECEIPT_HEADER: &str = "x-payment-receipt";

/// Default price for the premium demonstration route: 0.01 USDC (6 decimals).
const DEFAULT_PREMIUM_PRICE: u64 = 10_000;

/// Default recipient for the premium demonstration route (dev placeholder;
/// set `X402_PREMIUM_ROUTE_PAY_TO` in any real deployment).
const DEFAULT_PREMIUM_PAY_TO: &str = "0x0000000000000000000000000000000000000402";

// =============================================================================
// Configuration
// =============================================================================

/// Price/recipient configuration for a payment-gated route.
///
/// One instance gates one route (or one group of routes sharing a price);
/// construct additional instances to gate other routes at other prices.
#[derive(Debug, Clone)]
pub struct PaymentRequiredConfig {
    /// Minimum payment amount in the asset's smallest unit
    pub amount: u64,
    /// Required payment asset
    pub asset: X402Asset,
    /// Required settlement network
    pub network: X402Network,
    /// Recipient (payee) wallet address
    pub pay_to: String,
    /// Human-readable description advertised in the 402 challenge
    pub description: Option<String>,
}

impl PaymentRequiredConfig {
    /// Load the premium-route configuration from the environment, following
    /// the `X402_*` naming convention used by the batch worker:
    ///
    /// - `X402_PREMIUM_ROUTE_PRICE` — amount in smallest units (default 10000 = 0.01 USDC)
    /// - `X402_PREMIUM_ROUTE_ASSET` — asset (default `usdc`)
    /// - `X402_PREMIUM_ROUTE_NETWORK` — network (default `set_chain`)
    /// - `X402_PREMIUM_ROUTE_PAY_TO` — recipient wallet address
    /// - `X402_PREMIUM_ROUTE_DESCRIPTION` — optional challenge description
    pub fn from_env() -> Self {
        let amount = std::env::var("X402_PREMIUM_ROUTE_PRICE")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_PREMIUM_PRICE);

        let asset = std::env::var("X402_PREMIUM_ROUTE_ASSET")
            .ok()
            .and_then(|v| parse_enum_token::<X402Asset>(&v))
            .unwrap_or_default();

        let network = std::env::var("X402_PREMIUM_ROUTE_NETWORK")
            .ok()
            .and_then(|v| parse_enum_token::<X402Network>(&v))
            .unwrap_or_default();

        let pay_to = std::env::var("X402_PREMIUM_ROUTE_PAY_TO")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| {
                warn!(
                    "X402_PREMIUM_ROUTE_PAY_TO not set; using dev placeholder recipient {}",
                    DEFAULT_PREMIUM_PAY_TO
                );
                DEFAULT_PREMIUM_PAY_TO.to_string()
            });

        let description = std::env::var("X402_PREMIUM_ROUTE_DESCRIPTION")
            .ok()
            .filter(|v| !v.trim().is_empty());

        Self {
            amount,
            asset,
            network,
            pay_to,
            description,
        }
    }

    /// Build the payment requirements advertised for `resource` (the request
    /// path) in a 402 challenge.
    pub fn requirements_for(&self, resource: &str) -> X402PaymentRequirements {
        X402PaymentRequirements {
            x402_version: X402_VERSION,
            asset: self.asset,
            network: self.network,
            chain_id: self.network.chain_id(),
            token_address: self.asset.token_address(self.network).map(String::from),
            amount: self.amount,
            pay_to: self.pay_to.clone(),
            resource: resource.to_string(),
            description: self.description.clone(),
            max_validity_secs: X402_MAX_VALIDITY_SECS,
        }
    }
}

/// Parse a snake_case token (e.g. `"usdc"`, `"set_chain"`) into a
/// serde-deserializable enum such as [`X402Asset`] or [`X402Network`].
fn parse_enum_token<T: serde::de::DeserializeOwned>(value: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(value.trim().to_ascii_lowercase())).ok()
}

// =============================================================================
// Middleware State
// =============================================================================

/// State for [`payment_required_middleware`]: the repositories the payment
/// pipeline needs plus this route's price configuration.
#[derive(Clone)]
pub struct PaymentRequiredState {
    pub x402_repository: Arc<PgX402Repository>,
    pub agent_key_registry: Arc<PgAgentKeyRegistry>,
    pub config: Arc<PaymentRequiredConfig>,
}

impl PaymentRequiredState {
    pub fn new(
        x402_repository: Arc<PgX402Repository>,
        agent_key_registry: Arc<PgAgentKeyRegistry>,
        config: Arc<PaymentRequiredConfig>,
    ) -> Self {
        Self {
            x402_repository,
            agent_key_registry,
            config,
        }
    }
}

// =============================================================================
// Middleware
// =============================================================================

/// Axum middleware gating a route behind an x402 payment.
///
/// Apply with `axum::middleware::from_fn_with_state(gate_state, payment_required_middleware)`
/// (see [`crate::api::premium_router`] for the canonical wiring).
pub async fn payment_required_middleware(
    State(gate): State<PaymentRequiredState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // The auth middleware always runs first on API routes and inserts the
    // context (bootstrap admin when auth is disabled).
    let Some(AuthContextExt(auth)) = request.extensions().get::<AuthContextExt>().cloned() else {
        return ApiError::new(
            ErrorCode::AuthRequired,
            "Authentication context missing for payment-gated route",
        )
        .into_response();
    };

    // Use the original URI: nested routers (`/api`) strip their prefix from
    // `request.uri()`, but the advertised resource must be the client-facing
    // path.
    let resource = request
        .extensions()
        .get::<axum::extract::OriginalUri>()
        .map(|uri| uri.path().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());
    let requirements = gate.config.requirements_for(&resource);

    // 1. No X-Payment header -> issue the 402 challenge.
    let Some(header_value) = request.headers().get(X_PAYMENT_HEADER) else {
        debug!(resource = %resource, "Payment-gated route requested without X-Payment; issuing 402");
        return payment_required_error(
            "Payment required: sign the advertised payment intent and retry with an X-Payment header",
            &requirements,
        )
        .into_response();
    };

    // 2. Decode base64(JSON SubmitX402PaymentRequest).
    let mut payment = match decode_x_payment(header_value) {
        Ok(payment) => payment,
        Err(reason) => {
            debug!(resource = %resource, reason = %reason, "Invalid X-Payment header; re-issuing 402");
            return payment_required_error(
                format!("Invalid X-Payment header: {}", reason),
                &requirements,
            )
            .into_response();
        }
    };

    // 3. Check the intent against this route's requirements. Signature and
    //    expiry checks come later in the shared pipeline; these checks are the
    //    ones specific to the challenge (what must be paid, to whom).
    if let Err(reason) = check_against_requirements(&payment, &requirements) {
        debug!(resource = %resource, reason = %reason, "X-Payment does not satisfy requirements; re-issuing 402");
        return payment_required_error(reason, &requirements).into_response();
    }

    // 4. A header-presented intent is consumed by this request: drop any
    //    idempotency key (not part of the signed hash) so a replay cannot
    //    bypass nonce protection via the idempotency lookup, and record the
    //    resource this payment unlocked.
    payment.idempotency_key = None;
    payment.resource_uri = Some(resource.clone());

    // 5. Verify (signing hash, Ed25519 signature, expiry, permissions) and
    //    persist through the same path as POST /api/v1/x402/payments — the
    //    intent enters the normal batching pipeline and its nonce is burned.
    let sequenced = match verify_and_sequence_payment(
        &gate.x402_repository,
        &gate.agent_key_registry,
        &auth,
        payment,
    )
    .await
    {
        Ok(response) => response,
        Err(err) => return err.into_response(),
    };

    let receipt = X402PaymentReceiptHeader {
        intent_id: sequenced.intent_id,
        status: sequenced.status,
        sequence_number: sequenced.sequence_number.unwrap_or(0),
        sequenced_at: sequenced.sequenced_at,
        receipt_url: format!("/api/v1/x402/payments/{}/receipt", sequenced.intent_id),
    };

    info!(
        resource = %resource,
        intent_id = %receipt.intent_id,
        sequence_number = receipt.sequence_number,
        "x402 payment accepted for gated route"
    );

    // 6. Serve the resource and attach the receipt. The payment was sequenced
    //    regardless of the inner handler's outcome, so the receipt is always
    //    attached — it is the agent's proof of payment.
    let mut response = next.run(request).await;
    match encode_receipt_header(&receipt) {
        Ok(value) => {
            response
                .headers_mut()
                .insert(X_PAYMENT_RECEIPT_HEADER, value);
        }
        Err(e) => {
            // Should be unreachable (the receipt is plain serializable data);
            // log loudly but still serve the paid response.
            warn!(error = %e, intent_id = %receipt.intent_id, "Failed to encode X-Payment-Receipt header");
        }
    }
    response
}

// =============================================================================
// Helpers
// =============================================================================

/// Build the 402 error with the payment requirements attached as `details`.
fn payment_required_error(
    message: impl Into<String>,
    requirements: &X402PaymentRequirements,
) -> ApiError {
    let details = serde_json::to_value(requirements).unwrap_or_else(|e| {
        // Requirements are plain data; serialization cannot realistically
        // fail, but never panic in the request path.
        serde_json::json!({ "serialization_error": e.to_string() })
    });
    ApiError::new(ErrorCode::PaymentRequired, message).with_details(details)
}

/// Decode an `X-Payment` header: standard base64 of the JSON document
/// accepted by `POST /api/v1/x402/payments`.
fn decode_x_payment(value: &HeaderValue) -> Result<SubmitX402PaymentRequest, String> {
    let text = value
        .to_str()
        .map_err(|_| "header is not valid ASCII".to_string())?
        .trim();

    if text.is_empty() {
        return Err("header is empty".to_string());
    }

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|e| format!("invalid base64: {}", e))?;

    serde_json::from_slice::<SubmitX402PaymentRequest>(&bytes)
        .map_err(|e| format!("invalid payment intent JSON: {}", e))
}

/// Validate the decoded intent against the route's advertised requirements.
fn check_against_requirements(
    payment: &SubmitX402PaymentRequest,
    requirements: &X402PaymentRequirements,
) -> Result<(), String> {
    if payment.asset != requirements.asset {
        return Err(format!(
            "payment asset {:?} does not match required asset {:?}",
            payment.asset, requirements.asset
        ));
    }

    if payment.network != requirements.network {
        return Err(format!(
            "payment network {} does not match required network {}",
            payment.network, requirements.network
        ));
    }

    if !payment
        .payee_address
        .eq_ignore_ascii_case(&requirements.pay_to)
    {
        return Err(format!(
            "payment recipient does not match required pay_to {}",
            requirements.pay_to
        ));
    }

    if payment.amount < requirements.amount {
        return Err(format!(
            "payment amount {} is below the required amount {}",
            payment.amount, requirements.amount
        ));
    }

    // If the signed intent pins a resource, it must be the one requested.
    if let Some(ref resource_uri) = payment.resource_uri {
        if resource_uri != &requirements.resource {
            return Err(format!(
                "payment resource_uri {} does not match requested resource {}",
                resource_uri, requirements.resource
            ));
        }
    }

    Ok(())
}

/// Encode the receipt as base64(JSON) for the `X-Payment-Receipt` header.
fn encode_receipt_header(receipt: &X402PaymentReceiptHeader) -> Result<HeaderValue, String> {
    let json = serde_json::to_vec(receipt).map_err(|e| e.to_string())?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(json);
    HeaderValue::from_str(&encoded).map_err(|e| e.to_string())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_config() -> PaymentRequiredConfig {
        PaymentRequiredConfig {
            amount: 10_000,
            asset: X402Asset::Usdc,
            network: X402Network::SetChain,
            pay_to: "0x0000000000000000000000000000000000000402".to_string(),
            description: Some("test".to_string()),
        }
    }

    fn test_payment(config: &PaymentRequiredConfig) -> SubmitX402PaymentRequest {
        SubmitX402PaymentRequest {
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            agent_key_id: None,
            payer_address: "0xabc0000000000000000000000000000000000001".to_string(),
            payee_address: config.pay_to.clone(),
            amount: config.amount,
            asset: config.asset,
            network: config.network,
            valid_until: 4_000_000_000,
            nonce: 1,
            valid_after: None,
            signing_hash: format!("0x{}", "11".repeat(32)),
            payer_signature: format!("0x{}", "22".repeat(64)),
            payer_public_key: None,
            eip712_authorization: None,
            resource_uri: None,
            description: None,
            order_id: None,
            merchant_id: None,
            idempotency_key: None,
            metadata: None,
        }
    }

    #[test]
    fn test_requirements_for_resource() {
        let config = test_config();
        let req = config.requirements_for("/api/v1/x402/premium/insights");

        assert_eq!(req.x402_version, X402_VERSION);
        assert_eq!(req.amount, 10_000);
        assert_eq!(req.asset, X402Asset::Usdc);
        assert_eq!(req.network, X402Network::SetChain);
        assert_eq!(req.chain_id, X402Network::SetChain.chain_id());
        assert_eq!(req.pay_to, config.pay_to);
        assert_eq!(req.resource, "/api/v1/x402/premium/insights");
        assert_eq!(req.max_validity_secs, X402_MAX_VALIDITY_SECS);
    }

    #[test]
    fn test_requirements_serialize_snake_case_tokens() {
        let config = test_config();
        let req = config.requirements_for("/premium");
        let json = serde_json::to_value(&req).unwrap();

        assert_eq!(json["asset"], "usdc");
        assert_eq!(json["network"], "set_chain");
        assert_eq!(json["amount"], 10_000);
    }

    #[test]
    fn test_parse_enum_token() {
        assert_eq!(parse_enum_token::<X402Asset>("usdc"), Some(X402Asset::Usdc));
        assert_eq!(parse_enum_token::<X402Asset>("USDC"), Some(X402Asset::Usdc));
        assert_eq!(
            parse_enum_token::<X402Network>("set_chain"),
            Some(X402Network::SetChain)
        );
        assert_eq!(parse_enum_token::<X402Asset>("doge"), None);
    }

    #[test]
    fn test_decode_x_payment_roundtrip() {
        let config = test_config();
        let payment = test_payment(&config);
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&payment).unwrap());
        let header = HeaderValue::from_str(&encoded).unwrap();

        let decoded = decode_x_payment(&header).expect("roundtrip failed");
        assert_eq!(decoded.amount, payment.amount);
        assert_eq!(decoded.payee_address, payment.payee_address);
        assert_eq!(decoded.nonce, payment.nonce);
    }

    #[test]
    fn test_decode_x_payment_rejects_garbage() {
        assert!(decode_x_payment(&HeaderValue::from_static("!!nope!!")).is_err());
        assert!(decode_x_payment(&HeaderValue::from_static("")).is_err());

        let not_json = base64::engine::general_purpose::STANDARD.encode(b"not json");
        assert!(decode_x_payment(&HeaderValue::from_str(&not_json).unwrap()).is_err());
    }

    #[test]
    fn test_check_against_requirements() {
        let config = test_config();
        let requirements = config.requirements_for("/premium");

        // Exact match passes.
        let ok = test_payment(&config);
        assert!(check_against_requirements(&ok, &requirements).is_ok());

        // Overpayment passes.
        let mut overpaid = test_payment(&config);
        overpaid.amount = config.amount + 1;
        assert!(check_against_requirements(&overpaid, &requirements).is_ok());

        // Underpayment fails.
        let mut underpaid = test_payment(&config);
        underpaid.amount = config.amount - 1;
        assert!(check_against_requirements(&underpaid, &requirements).is_err());

        // Wrong recipient fails.
        let mut wrong_payee = test_payment(&config);
        wrong_payee.payee_address = "0x00000000000000000000000000000000000000ff".to_string();
        assert!(check_against_requirements(&wrong_payee, &requirements).is_err());

        // Recipient comparison is case-insensitive (hex addresses).
        let mut upper_payee = test_payment(&config);
        upper_payee.payee_address = config.pay_to.to_uppercase();
        assert!(check_against_requirements(&upper_payee, &requirements).is_ok());

        // Wrong asset fails.
        let mut wrong_asset = test_payment(&config);
        wrong_asset.asset = X402Asset::Dai;
        assert!(check_against_requirements(&wrong_asset, &requirements).is_err());

        // Wrong network fails.
        let mut wrong_network = test_payment(&config);
        wrong_network.network = X402Network::Base;
        assert!(check_against_requirements(&wrong_network, &requirements).is_err());

        // Mismatched pinned resource fails; matching one passes.
        let mut wrong_resource = test_payment(&config);
        wrong_resource.resource_uri = Some("/other".to_string());
        assert!(check_against_requirements(&wrong_resource, &requirements).is_err());

        let mut right_resource = test_payment(&config);
        right_resource.resource_uri = Some("/premium".to_string());
        assert!(check_against_requirements(&right_resource, &requirements).is_ok());
    }

    #[test]
    fn test_encode_receipt_header_roundtrip() {
        let receipt = X402PaymentReceiptHeader {
            intent_id: Uuid::new_v4(),
            status: crate::domain::X402IntentStatus::Sequenced,
            sequence_number: 42,
            sequenced_at: Some(chrono::Utc::now()),
            receipt_url: format!("/api/v1/x402/payments/{}/receipt", Uuid::new_v4()),
        };

        let header = encode_receipt_header(&receipt).unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(header.to_str().unwrap())
            .unwrap();
        let decoded: X402PaymentReceiptHeader = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(decoded.intent_id, receipt.intent_id);
        assert_eq!(decoded.sequence_number, 42);
    }
}
