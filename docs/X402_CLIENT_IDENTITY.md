# Client-reserved x402 payment identity

The x402 router's `GET /capabilities` advertises
`x402.client_intent_id.v1` with `intent_id_encoding` equal to
`uuid-prefix-zero-pad-bytes32`. Apply the same router prefix used for payments.

Before constructing a Set `PaymentAuthorization`, reserve a non-nil UUID in the
client's durable journal. Encode the UUID's 16 bytes followed by 16 zero bytes as
the contract's bytes32 `intentId`. Sign that identity and send the UUID as
`intent_id` alongside `eip712_authorization` in the payment request. Preserve the
same ID, nonce, authorization and idempotency key across retries.

Requests carrying `eip712_authorization` without `intent_id` are rejected. This
is intentional: a server-assigned identity cannot match a pre-existing signature.
Legacy requests without on-chain authorization may omit the ID.

Idempotent retries are authenticated before lookup. Submissions with the same
tenant/store/idempotency key use a transaction-scoped PostgreSQL advisory lock;
immutable request mismatches return a version conflict instead of returning an
unrelated earlier result. Read failures propagate. After expiry, use intent GET
or receipt GET to reconcile; POST expiry validation still applies to retries.

This capability promises identity handling, not payer-signature verification at
admission. The authorization blob is shape-checked here and verified by Set on
chain. The response explicitly reports
`settlement_authorization_validation: "on-chain"`. Admission-time EOA/ERC-1271
verification, real PostgreSQL concurrency tests and full commerce-to-settlement
integration tests remain release gates. No live money is needed for unit tests.
