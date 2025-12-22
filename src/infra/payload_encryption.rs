//! Payload encryption-at-rest configuration and helpers.

use std::sync::Arc;

use uuid::Uuid;

use crate::crypto::{
    compute_payload_at_rest_aad, decrypt_payload_at_rest, encrypt_payload_at_rest,
    is_payload_at_rest_encrypted, EncryptionError, InMemoryKeyManager, KeyManager,
};
use crate::domain::{EventEnvelope, Hash256};
use crate::infra::{Result, SequencerError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadEncryptionMode {
    Disabled,
    Optional,
    Required,
}

impl PayloadEncryptionMode {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "disabled" | "off" | "false" | "0" => Ok(Self::Disabled),
            "optional" => Ok(Self::Optional),
            "required" | "on" | "true" | "1" => Ok(Self::Required),
            other => Err(SequencerError::Configuration(format!(
                "invalid PAYLOAD_ENCRYPTION_MODE={other} (expected: disabled|optional|required)"
            ))),
        }
    }
}

#[derive(Clone)]
pub struct PayloadEncryption {
    mode: PayloadEncryptionMode,
    key_manager: Arc<dyn KeyManager>,
}

impl PayloadEncryption {
    pub fn new(mode: PayloadEncryptionMode, key_manager: Arc<dyn KeyManager>) -> Self {
        Self { mode, key_manager }
    }

    pub fn disabled() -> Self {
        Self {
            mode: PayloadEncryptionMode::Disabled,
            key_manager: Arc::new(InMemoryKeyManager::new()),
        }
    }

    pub fn mode(&self) -> PayloadEncryptionMode {
        self.mode
    }

    pub fn from_env() -> Result<Self> {
        let mode_str =
            std::env::var("PAYLOAD_ENCRYPTION_MODE").unwrap_or_else(|_| "required".to_string());
        let mode = PayloadEncryptionMode::parse(&mode_str)?;
        Self::from_env_with_mode(mode)
    }

    pub fn from_env_with_mode(mode: PayloadEncryptionMode) -> Result<Self> {
        if mode == PayloadEncryptionMode::Disabled {
            return Ok(Self::disabled());
        }

        let tenant_keys_json = std::env::var("PAYLOAD_ENCRYPTION_KEYS_BY_TENANT").ok();

        let default_keyring = match std::env::var("PAYLOAD_ENCRYPTION_KEYS") {
            Ok(keys) => parse_keyring_list(&keys)?,
            Err(_) => {
                let key_str = std::env::var("PAYLOAD_ENCRYPTION_KEY").map_err(|_| {
                    SequencerError::Configuration(
                        "PAYLOAD_ENCRYPTION_KEY (or PAYLOAD_ENCRYPTION_KEYS) is required unless PAYLOAD_ENCRYPTION_MODE=disabled"
                            .to_string(),
                    )
                })?;
                vec![parse_32_byte_key(&key_str)?]
            }
        };

        let tenant_keys = tenant_keys_json
            .as_deref()
            .map(parse_tenant_keyrings)
            .transpose()?
            .unwrap_or_default();

        let key_manager: Arc<dyn KeyManager> =
            Arc::new(EnvKeyManager::new(default_keyring, tenant_keys));
        Ok(Self::new(mode, key_manager))
    }

    pub fn aad_for_event(envelope: &EventEnvelope, sequence_number: u64) -> Hash256 {
        compute_payload_at_rest_aad(
            &envelope.tenant_id.0,
            &envelope.store_id.0,
            &envelope.event_id,
            sequence_number,
            envelope.entity_type.as_str(),
            &envelope.entity_id,
            envelope.event_type.as_str(),
        )
    }

    pub fn aad_for_row(
        tenant_id: &Uuid,
        store_id: &Uuid,
        event_id: &Uuid,
        sequence_number: u64,
        entity_type: &str,
        entity_id: &str,
        event_type: &str,
    ) -> Hash256 {
        compute_payload_at_rest_aad(
            tenant_id,
            store_id,
            event_id,
            sequence_number,
            entity_type,
            entity_id,
            event_type,
        )
    }

    pub async fn encrypt_payload(
        &self,
        tenant_id: &Uuid,
        aad: &Hash256,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        match self.mode {
            PayloadEncryptionMode::Disabled => Ok(plaintext.to_vec()),
            PayloadEncryptionMode::Optional | PayloadEncryptionMode::Required => {
                let keys = self
                    .key_manager
                    .get_tenant_keys(tenant_id)
                    .await
                    .map_err(|e| SequencerError::Encryption(e.to_string()))?;

                let Some(key) = keys.first().copied() else {
                    return Err(SequencerError::Encryption(
                        "no encryption keys configured".to_string(),
                    ));
                };

                encrypt_payload_at_rest(&key, aad, plaintext)
                    .map_err(|e| SequencerError::Encryption(e.to_string()))
            }
        }
    }

    pub async fn decrypt_payload(
        &self,
        tenant_id: &Uuid,
        aad: &Hash256,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if !is_payload_at_rest_encrypted(ciphertext) {
            return match self.mode {
                PayloadEncryptionMode::Required => Err(SequencerError::Encryption(
                    "payload is not encrypted at rest (required)".to_string(),
                )),
                PayloadEncryptionMode::Disabled | PayloadEncryptionMode::Optional => {
                    Ok(ciphertext.to_vec())
                }
            };
        }

        let keys = self
            .key_manager
            .get_tenant_keys(tenant_id)
            .await
            .map_err(|e| SequencerError::Encryption(e.to_string()))?;

        let mut last_error: Option<EncryptionError> = None;
        for key in keys {
            match decrypt_payload_at_rest(&key, aad, ciphertext) {
                Ok(plaintext) => return Ok(plaintext),
                Err(e @ EncryptionError::DecryptionFailed(_)) => {
                    last_error = Some(e);
                    continue;
                }
                Err(e) => return Err(SequencerError::Encryption(e.to_string())),
            }
        }

        Err(SequencerError::Encryption(
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "decryption failed (no keys)".to_string()),
        ))
    }

    pub async fn decrypt_payload_with_current_key(
        &self,
        tenant_id: &Uuid,
        aad: &Hash256,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if !is_payload_at_rest_encrypted(ciphertext) {
            return match self.mode {
                PayloadEncryptionMode::Required => Err(SequencerError::Encryption(
                    "payload is not encrypted at rest (required)".to_string(),
                )),
                PayloadEncryptionMode::Disabled | PayloadEncryptionMode::Optional => {
                    Ok(ciphertext.to_vec())
                }
            };
        }

        let keys = self
            .key_manager
            .get_tenant_keys(tenant_id)
            .await
            .map_err(|e| SequencerError::Encryption(e.to_string()))?;

        let Some(key) = keys.first().copied() else {
            return Err(SequencerError::Encryption(
                "no encryption keys configured".to_string(),
            ));
        };

        decrypt_payload_at_rest(&key, aad, ciphertext)
            .map_err(|e| SequencerError::Encryption(e.to_string()))
    }
}

fn parse_32_byte_key(s: &str) -> Result<[u8; 32]> {
    let trimmed = s.trim();
    let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);

    if hex_str.len() == 64 && hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = hex::decode(hex_str).map_err(|e| {
            SequencerError::Configuration(format!("invalid PAYLOAD_ENCRYPTION_KEY hex: {e}"))
        })?;
        return bytes.try_into().map_err(|_| {
            SequencerError::Configuration("PAYLOAD_ENCRYPTION_KEY must be 32 bytes".to_string())
        });
    }

    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, trimmed)
        .or_else(|_| {
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, trimmed)
        })
        .map_err(|e| {
            SequencerError::Configuration(format!("invalid PAYLOAD_ENCRYPTION_KEY base64: {e}"))
        })?;

    bytes.try_into().map_err(|_| {
        SequencerError::Configuration("PAYLOAD_ENCRYPTION_KEY must be 32 bytes".to_string())
    })
}

fn parse_keyring_list(s: &str) -> Result<Vec<[u8; 32]>> {
    let keys: Vec<&str> = s
        .split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .collect();
    if keys.is_empty() {
        return Err(SequencerError::Configuration(
            "PAYLOAD_ENCRYPTION_KEYS must contain at least one key".to_string(),
        ));
    }
    keys.into_iter().map(parse_32_byte_key).collect()
}

fn parse_tenant_keyrings(json: &str) -> Result<std::collections::HashMap<Uuid, Vec<[u8; 32]>>> {
    let map: std::collections::HashMap<String, Vec<String>> =
        serde_json::from_str(json).map_err(|e| {
            SequencerError::Configuration(format!(
                "invalid PAYLOAD_ENCRYPTION_KEYS_BY_TENANT JSON: {e}"
            ))
        })?;

    let mut out = std::collections::HashMap::new();
    for (tenant_str, keys) in map {
        let tenant_id = Uuid::parse_str(&tenant_str).map_err(|e| {
            SequencerError::Configuration(format!(
                "invalid tenant UUID in PAYLOAD_ENCRYPTION_KEYS_BY_TENANT: {tenant_str} ({e})"
            ))
        })?;

        if keys.is_empty() {
            return Err(SequencerError::Configuration(format!(
                "tenant {tenant_id} keyring is empty"
            )));
        }

        let mut parsed = Vec::with_capacity(keys.len());
        for key in keys {
            parsed.push(parse_32_byte_key(&key)?);
        }
        out.insert(tenant_id, parsed);
    }

    Ok(out)
}

struct EnvKeyManager {
    default_keys: Vec<[u8; 32]>,
    tenant_keys: std::collections::HashMap<Uuid, Vec<[u8; 32]>>,
}

impl EnvKeyManager {
    fn new(
        default_keys: Vec<[u8; 32]>,
        tenant_keys: std::collections::HashMap<Uuid, Vec<[u8; 32]>>,
    ) -> Self {
        Self {
            default_keys,
            tenant_keys,
        }
    }
}

#[async_trait::async_trait]
impl KeyManager for EnvKeyManager {
    async fn get_tenant_keys(
        &self,
        tenant_id: &Uuid,
    ) -> std::result::Result<Vec<[u8; 32]>, EncryptionError> {
        Ok(self
            .tenant_keys
            .get(tenant_id)
            .cloned()
            .unwrap_or_else(|| self.default_keys.clone()))
    }

    async fn rotate_tenant_key(
        &self,
        _tenant_id: &Uuid,
    ) -> std::result::Result<[u8; 32], EncryptionError> {
        Err(EncryptionError::KeyDerivationFailed(
            "EnvKeyManager does not support rotation at runtime".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn decrypt_tries_multiple_keys() {
        let tenant = Uuid::new_v4();
        let store = Uuid::new_v4();
        let event_id = Uuid::new_v4();

        let key_old = crate::crypto::generate_key();
        let key_new = crate::crypto::generate_key();

        let aad = crate::crypto::compute_payload_at_rest_aad(
            &tenant,
            &store,
            &event_id,
            1,
            "order",
            "order-1",
            "order.created",
        );

        let ciphertext = crate::crypto::encrypt_payload_at_rest(&key_old, &aad, b"hello").unwrap();

        let key_manager = Arc::new(EnvKeyManager::new(
            vec![key_new, key_old],
            Default::default(),
        ));
        let enc = PayloadEncryption::new(PayloadEncryptionMode::Required, key_manager);

        let plaintext = enc
            .decrypt_payload(&tenant, &aad, &ciphertext)
            .await
            .unwrap();
        assert_eq!(plaintext, b"hello");
    }
}
