//! Common test utilities and fixtures for integration tests

#![allow(dead_code)]

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

/// Test tenant ID
pub fn test_tenant_id() -> Uuid {
    Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
}

/// Test store ID
pub fn test_store_id() -> Uuid {
    Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()
}

/// Test agent ID
pub fn test_agent_id() -> Uuid {
    Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()
}

/// Generate a random event ID
pub fn random_event_id() -> Uuid {
    Uuid::new_v4()
}

/// Generate a random entity ID
pub fn random_entity_id(prefix: &str) -> String {
    format!("{}-{}", prefix, &Uuid::new_v4().to_string()[..8])
}

/// Compute SHA-256 hash of JSON payload
pub fn compute_payload_hash(payload: &serde_json::Value) -> [u8; 32] {
    stateset_sequencer::crypto::canonical_json_hash(payload)
}

/// Create a test order.created event payload
pub fn order_created_payload(customer_id: &str, total: f64) -> serde_json::Value {
    json!({
        "customer_id": customer_id,
        "total_amount": total,
        "currency": "USD",
        "line_items": [
            {
                "product_id": "prod-001",
                "quantity": 2,
                "unit_price": total / 2.0
            }
        ],
        "shipping_address": {
            "street": "123 Test St",
            "city": "Test City",
            "country": "US"
        }
    })
}

/// Create a test order status change event payload
pub fn order_status_payload(new_status: &str) -> serde_json::Value {
    json!({
        "status": new_status,
        "updated_at": Utc::now().to_rfc3339()
    })
}

/// Create a test inventory.initialized event payload
pub fn inventory_initialized_payload(quantity: i64) -> serde_json::Value {
    json!({
        "quantity": quantity,
        "reorder_point": 10,
        "location": "warehouse-1"
    })
}

/// Create a test inventory.adjusted event payload
pub fn inventory_adjusted_payload(adjustment: i64, reason: &str) -> serde_json::Value {
    json!({
        "adjustment": adjustment,
        "reason": reason,
        "adjusted_by": "system"
    })
}

/// Create a test product.created event payload
pub fn product_created_payload(sku: &str, name: &str, price: f64) -> serde_json::Value {
    json!({
        "sku": sku,
        "name": name,
        "description": format!("Test product: {}", name),
        "price": price,
        "currency": "USD",
        "attributes": {
            "color": "blue",
            "size": "medium"
        }
    })
}

/// Create a test customer.created event payload
pub fn customer_created_payload(email: &str, name: &str) -> serde_json::Value {
    json!({
        "email": email,
        "name": name,
        "phone": "+1-555-0100",
        "metadata": {
            "source": "integration-test"
        }
    })
}

/// Create a test return.requested event payload
pub fn return_requested_payload(
    order_id: &str,
    customer_id: &str,
    reason: &str,
) -> serde_json::Value {
    json!({
        "order_id": order_id,
        "customer_id": customer_id,
        "reason": reason,
        "items": [
            {
                "product_id": "prod-001",
                "quantity": 1
            }
        ]
    })
}

/// Event builder for creating test events
pub struct TestEventBuilder {
    event_id: Uuid,
    command_id: Option<Uuid>,
    tenant_id: Uuid,
    store_id: Uuid,
    entity_type: String,
    entity_id: String,
    event_type: String,
    payload: serde_json::Value,
    base_version: Option<u64>,
    source_agent: Uuid,
}

impl TestEventBuilder {
    pub fn new() -> Self {
        Self {
            event_id: Uuid::new_v4(),
            command_id: None,
            tenant_id: test_tenant_id(),
            store_id: test_store_id(),
            entity_type: "order".to_string(),
            entity_id: random_entity_id("ord"),
            event_type: "order.created".to_string(),
            payload: json!({}),
            base_version: None,
            source_agent: test_agent_id(),
        }
    }

    pub fn event_id(mut self, id: Uuid) -> Self {
        self.event_id = id;
        self
    }

    pub fn command_id(mut self, id: Uuid) -> Self {
        self.command_id = Some(id);
        self
    }

    pub fn tenant_id(mut self, id: Uuid) -> Self {
        self.tenant_id = id;
        self
    }

    pub fn store_id(mut self, id: Uuid) -> Self {
        self.store_id = id;
        self
    }

    pub fn entity_type(mut self, t: &str) -> Self {
        self.entity_type = t.to_string();
        self
    }

    pub fn entity_id(mut self, id: &str) -> Self {
        self.entity_id = id.to_string();
        self
    }

    pub fn event_type(mut self, t: &str) -> Self {
        self.event_type = t.to_string();
        self
    }

    pub fn payload(mut self, p: serde_json::Value) -> Self {
        self.payload = p;
        self
    }

    pub fn base_version(mut self, v: u64) -> Self {
        self.base_version = Some(v);
        self
    }

    pub fn source_agent(mut self, id: Uuid) -> Self {
        self.source_agent = id;
        self
    }

    /// Build the event as a JSON value (for REST API testing)
    pub fn build_json(self) -> serde_json::Value {
        let payload_hash = compute_payload_hash(&self.payload);

        json!({
            "event_id": self.event_id.to_string(),
            "command_id": self.command_id.map(|id| id.to_string()),
            "tenant_id": self.tenant_id.to_string(),
            "store_id": self.store_id.to_string(),
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "event_type": self.event_type,
            "payload": self.payload,
            "payload_hash": hex::encode(payload_hash),
            "base_version": self.base_version,
            "created_at": Utc::now().to_rfc3339(),
            "source_agent": self.source_agent.to_string()
        })
    }
}

impl Default for TestEventBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Assert that two hash arrays are equal
pub fn assert_hash_eq(a: &[u8; 32], b: &[u8; 32]) {
    assert_eq!(hex::encode(a), hex::encode(b), "Hash mismatch");
}

/// Assert that a result is Ok and return the value
#[macro_export]
macro_rules! assert_ok {
    ($result:expr) => {
        match $result {
            Ok(v) => v,
            Err(e) => panic!("Expected Ok, got Err: {:?}", e),
        }
    };
}

/// Assert that a result is Err
#[macro_export]
macro_rules! assert_err {
    ($result:expr) => {
        match $result {
            Ok(v) => panic!("Expected Err, got Ok: {:?}", v),
            Err(e) => e,
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_builder() {
        let event = TestEventBuilder::new()
            .entity_type("order")
            .entity_id("ord-123")
            .event_type("order.created")
            .payload(order_created_payload("cust-456", 100.0))
            .build_json();

        assert_eq!(event["entity_type"], "order");
        assert_eq!(event["entity_id"], "ord-123");
        assert_eq!(event["event_type"], "order.created");
        assert!(event["payload"]["customer_id"].as_str().is_some());
    }

    #[test]
    fn test_payload_hash() {
        let payload = json!({"key": "value"});
        let hash1 = compute_payload_hash(&payload);
        let hash2 = compute_payload_hash(&payload);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }
}
