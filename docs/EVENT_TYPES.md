# Event Types Reference

This document describes all supported event types in the StateSet Sequencer, their payload schemas, and state transitions.

## Event Structure

All events follow the VES v1.0 envelope format:

```json
{
  "ves_version": 1,
  "event_id": "uuid",
  "tenant_id": "uuid",
  "store_id": "uuid",
  "agent_id": "uuid",
  "agent_key_id": 1,
  "entity_type": "order",
  "entity_id": "order-123",
  "event_type": "order.created",
  "payload": { ... },
  "payload_kind": 0,
  "payload_plain_hash": "hex-sha256",
  "occurred_at": "2024-01-15T10:30:00Z",
  "agent_signature": "hex-ed25519-signature"
}
```

## Order Events

Entity Type: `order`

### order.created

Creates a new order.

**Payload:**
```json
{
  "customer_id": "cust-123",
  "total_amount": 99.99,
  "currency": "USD",
  "line_items": [
    {
      "product_id": "prod-456",
      "quantity": 2,
      "unit_price": 49.99
    }
  ],
  "shipping_address": {
    "street": "123 Main St",
    "city": "San Francisco",
    "state": "CA",
    "postal_code": "94102",
    "country": "US"
  }
}
```

**Required Fields:**
- `customer_id` (string)

**Optional Fields:**
- `total_amount` (number, default: 0)
- `currency` (string, default: "USD")
- `line_items` (array)
- `shipping_address` (object)

**Resulting State:**
```json
{
  "order_id": "order-123",
  "customer_id": "cust-123",
  "status": "pending",
  "total_amount": 99.99,
  "currency": "USD",
  "line_items": [...],
  "shipping_address": {...},
  "version": 1,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### order.confirmed

Confirms a pending order.

**Payload:**
```json
{
  "confirmed_by": "user-789",
  "confirmation_number": "CONF-001"
}
```

**Valid Transitions:** `pending` → `confirmed`

**Rejected If:**
- Order does not exist
- Order status is not `pending`

### order.processing

Marks order as being processed.

**Payload:**
```json
{
  "warehouse_id": "wh-001",
  "estimated_ship_date": "2024-01-17"
}
```

**Valid Transitions:** `confirmed` → `processing`

### order.shipped

Marks order as shipped.

**Payload:**
```json
{
  "carrier": "UPS",
  "tracking_number": "1Z999AA10123456784",
  "shipped_at": "2024-01-17T14:00:00Z"
}
```

**Valid Transitions:** `processing` → `shipped`

### order.delivered

Marks order as delivered.

**Payload:**
```json
{
  "delivered_at": "2024-01-19T10:30:00Z",
  "signed_by": "John Doe"
}
```

**Valid Transitions:** `shipped` → `delivered`

### order.cancelled

Cancels an order.

**Payload:**
```json
{
  "reason": "customer_request",
  "cancelled_by": "user-789",
  "refund_amount": 99.99
}
```

**Valid Transitions:** Any status except `delivered` → `cancelled`

**Rejected If:**
- Order status is `delivered`

### Order State Machine

```
                    ┌──────────────┐
                    │   pending    │
                    └──────┬───────┘
                           │ order.confirmed
                           ▼
                    ┌──────────────┐
           ┌───────│  confirmed   │
           │       └──────┬───────┘
           │              │ order.processing
           │              ▼
           │       ┌──────────────┐
           │       │  processing  │────────┐
           │       └──────┬───────┘        │
           │              │ order.shipped   │
           │              ▼                 │
           │       ┌──────────────┐        │
           │       │   shipped    │────────┤
           │       └──────┬───────┘        │
           │              │ order.delivered │
           │              ▼                 │
           │       ┌──────────────┐        │
           │       │  delivered   │        │
           │       └──────────────┘        │
           │                               │
           │ order.cancelled               │ order.cancelled
           │                               │
           └──────────┐    ┌───────────────┘
                      ▼    ▼
                ┌──────────────┐
                │  cancelled   │
                └──────────────┘
```

---

## Inventory Events

Entity Type: `inventory`

Entity ID Format: `{product_id}` or `{product_id}:{location_id}`

### inventory.initialized

Initializes inventory for a product at a location.

**Payload:**
```json
{
  "quantity": 100,
  "reorder_point": 20,
  "location_id": "warehouse-001"
}
```

**Required Fields:**
- None (defaults apply)

**Optional Fields:**
- `quantity` (number, default: 0)
- `reorder_point` (number, default: 10)
- `location_id` (string, default: from entity_id)

**Resulting State:**
```json
{
  "product_id": "prod-123",
  "location_id": "warehouse-001",
  "quantity_on_hand": 100,
  "quantity_reserved": 0,
  "quantity_available": 100,
  "reorder_point": 20,
  "version": 1,
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### inventory.adjusted

Adjusts inventory quantity (add or remove stock).

**Payload:**
```json
{
  "adjustment": -5,
  "reason": "damaged_goods",
  "reference": "ADJ-001"
}
```

**Required Fields:**
- `adjustment` (number) - positive to add, negative to remove

**Invariants:**
- `quantity_on_hand` cannot go negative

**Rejected If:**
- Inventory not initialized
- Adjustment would result in negative quantity

### inventory.reserved

Reserves inventory for an order.

**Payload:**
```json
{
  "quantity": 2,
  "order_id": "order-123"
}
```

**Required Fields:**
- `quantity` (number)

**Invariants:**
- `quantity_reserved` cannot exceed `quantity_available`

**Rejected If:**
- Insufficient available quantity

### inventory.released

Releases previously reserved inventory.

**Payload:**
```json
{
  "quantity": 2,
  "order_id": "order-123",
  "reason": "order_cancelled"
}
```

**Required Fields:**
- `quantity` (number)

### inventory.fulfilled

Removes inventory when an order ships.

**Payload:**
```json
{
  "quantity": 2,
  "order_id": "order-123"
}
```

**Effect:**
- Decreases `quantity_on_hand`
- Decreases `quantity_reserved`
- Recalculates `quantity_available`

---

## Product Events

Entity Type: `product`

### product.created

Creates a new product.

**Payload:**
```json
{
  "sku": "SKU-001",
  "name": "Widget Pro",
  "description": "A professional-grade widget",
  "price": 49.99,
  "currency": "USD",
  "attributes": {
    "color": "blue",
    "size": "medium",
    "weight_kg": 0.5
  }
}
```

**Required Fields:**
- None (defaults apply)

**Optional Fields:**
- `sku` (string)
- `name` (string)
- `description` (string)
- `price` (number, default: 0)
- `currency` (string, default: "USD")
- `attributes` (object)

**Resulting State:**
```json
{
  "product_id": "prod-123",
  "sku": "SKU-001",
  "name": "Widget Pro",
  "description": "A professional-grade widget",
  "price": 49.99,
  "currency": "USD",
  "active": true,
  "attributes": {...},
  "version": 1,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### product.updated

Updates product information.

**Payload:**
```json
{
  "name": "Widget Pro 2.0",
  "price": 59.99,
  "attributes": {
    "color": "red"
  }
}
```

All fields are optional; only provided fields are updated.

### product.deactivated

Deactivates a product (soft delete).

**Payload:**
```json
{
  "reason": "discontinued",
  "deactivated_by": "user-789"
}
```

**Effect:** Sets `active` to `false`

### product.activated

Reactivates a deactivated product.

**Payload:**
```json
{
  "activated_by": "user-789"
}
```

**Effect:** Sets `active` to `true`

---

## Customer Events

Entity Type: `customer`

### customer.created

Creates a new customer.

**Payload:**
```json
{
  "email": "john@example.com",
  "name": "John Doe",
  "phone": "+1-555-123-4567",
  "metadata": {
    "source": "website",
    "campaign": "summer-2024"
  }
}
```

**Required Fields:**
- `email` (string)

**Optional Fields:**
- `name` (string)
- `phone` (string)
- `metadata` (object)

**Resulting State:**
```json
{
  "customer_id": "cust-123",
  "email": "john@example.com",
  "name": "John Doe",
  "phone": "+1-555-123-4567",
  "addresses": [],
  "metadata": {...},
  "active": true,
  "version": 1,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### customer.updated

Updates customer information.

**Payload:**
```json
{
  "email": "john.doe@example.com",
  "name": "John M. Doe",
  "metadata": {
    "vip": true
  }
}
```

### customer.address_added

Adds a new address to the customer.

**Payload:**
```json
{
  "address": {
    "label": "home",
    "street": "123 Main St",
    "city": "San Francisco",
    "state": "CA",
    "postal_code": "94102",
    "country": "US",
    "is_default": true
  }
}
```

**Effect:** Appends address to `addresses` array

---

## Return Events

Entity Type: `return`

### return.requested

Initiates a return request.

**Payload:**
```json
{
  "order_id": "order-123",
  "customer_id": "cust-456",
  "reason": "defective",
  "items": [
    {
      "product_id": "prod-789",
      "quantity": 1,
      "condition": "unopened"
    }
  ]
}
```

**Required Fields:**
- `order_id` (string)
- `customer_id` (string)

**Optional Fields:**
- `reason` (string)
- `items` (array)

**Resulting State:**
```json
{
  "return_id": "ret-001",
  "order_id": "order-123",
  "customer_id": "cust-456",
  "status": "requested",
  "reason": "defective",
  "items": [...],
  "refund_amount": null,
  "version": 1,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### return.approved

Approves a return request.

**Payload:**
```json
{
  "approved_by": "user-789",
  "return_label": "RMA-001"
}
```

**Valid Transitions:** `requested` → `approved`

### return.rejected

Rejects a return request.

**Payload:**
```json
{
  "rejected_by": "user-789",
  "reason": "outside_return_window"
}
```

**Valid Transitions:** `requested` → `rejected`

### return.received

Marks returned items as received.

**Payload:**
```json
{
  "received_at": "2024-01-20T14:00:00Z",
  "received_by": "warehouse-user",
  "condition_notes": "Items in good condition"
}
```

**Valid Transitions:** `approved` → `received`

### return.refunded

Records refund issuance.

**Payload:**
```json
{
  "refund_amount": 49.99,
  "refund_method": "original_payment",
  "transaction_id": "txn-123"
}
```

**Valid Transitions:** `received` → `refunded`

### return.completed

Marks return as fully completed.

**Payload:**
```json
{
  "completed_at": "2024-01-22T10:00:00Z",
  "inventory_restocked": true
}
```

**Valid Transitions:** `refunded` → `completed`

### Return State Machine

```
              ┌──────────────┐
              │  requested   │
              └──────┬───────┘
                     │
         ┌───────────┴───────────┐
         │                       │
         ▼                       ▼
  ┌──────────────┐       ┌──────────────┐
  │   approved   │       │   rejected   │
  └──────┬───────┘       └──────────────┘
         │
         ▼
  ┌──────────────┐
  │   received   │
  └──────┬───────┘
         │
         ▼
  ┌──────────────┐
  │   refunded   │
  └──────┬───────┘
         │
         ▼
  ┌──────────────┐
  │  completed   │
  └──────────────┘
```

---

## System Events

Entity Type: `system`

### event.rejected

Emitted when an event fails projection validation.

**Payload (auto-generated):**
```json
{
  "original_event_id": "evt-123",
  "original_event_type": "order.shipped",
  "rejection_reason": "invalid_state_transition",
  "message": "Cannot ship order in 'pending' status"
}
```

This event is created by the projector, not by agents.

---

## Custom Event Types

You can define custom event types by following the naming convention:

```
{entity_type}.{action}
```

Examples:
- `subscription.created`
- `subscription.renewed`
- `payment.processed`
- `shipment.tracking_updated`

Custom events that don't have a registered handler will be stored but skipped during projection.

---

## Validation Rules

### Event ID

- Must be a valid UUID v4
- Must be unique across all events
- Duplicate event IDs are rejected (idempotency)

### Timestamps

- Must be valid ISO 8601 / RFC 3339 format
- Cannot be more than 1 hour in the future
- Example: `2024-01-15T10:30:00.000Z`

### Entity IDs

- Maximum 256 characters
- Allowed characters: alphanumeric, `-`, `_`, `:`
- Case-sensitive

### Payload

- Must be valid JSON
- Maximum size: 1 MB (configurable)
- UTF-8 encoded

### Event Types

- Format: `{entity_type}.{action}`
- Maximum 128 characters
- Lowercase with dots and underscores

---

## Best Practices

### Event Naming

- Use past tense for completed actions: `order.created`, `payment.processed`
- Use present tense for ongoing states: `order.processing`
- Be specific: `inventory.adjusted` vs generic `inventory.changed`

### Payload Design

- Include only necessary data
- Don't duplicate data stored elsewhere
- Include context for debugging (e.g., `adjusted_by`, `reason`)

### Idempotency

- Use deterministic `event_id` generation when possible
- Include business keys in payload for correlation

### Versioning

- Payload schema changes should be backward compatible
- Add new optional fields rather than changing existing ones
- Consider event type versioning for breaking changes: `order.created.v2`
