from __future__ import annotations

import json

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stateset_sequencer import (
    AsyncSequencerClient,
    SequencerApiError,
    SequencerClient,
    canonicalize_json,
    compute_event_signing_hash,
    compute_payload_plain_hash,
    create_async_tool_executor,
    create_tool_executor,
    verify_inclusion_proof_locally,
)


def test_offline_inclusion_binds_trusted_root_leaf_and_position():
    root = "5186fbc7094f70b9fc71bcf269fda0530c1c2bd675de918ef39562a6f18752fd"
    leaf, sibling = "01" * 32, "02" * 32
    proof = {
        "merkle_root": root,
        "leaf_hash": leaf,
        "leaf_index": 0,
        "proof_path": [sibling],
        "directions": [True],
    }
    assert verify_inclusion_proof_locally(proof, root, leaf)
    assert verify_inclusion_proof_locally(
        {
            **proof,
            "leaf_hash": sibling,
            "leaf_index": 1,
            "proof_path": [leaf],
            "directions": [False],
        },
        root,
        sibling,
    )
    for change in [
        {"directions": [False]},
        {"directions": []},
        {"leaf_index": 2},
        {"directions": [1]},
        {"leaf_index": True},
        {"proof_path": [leaf]},
        {"leaf_hash": sibling},
        {"merkle_root": leaf},
        {"proof_path": [sibling] * 65, "directions": [True] * 65},
    ]:
        assert not verify_inclusion_proof_locally({**proof, **change}, root, leaf)
    assert not verify_inclusion_proof_locally(proof, sibling, leaf)
    assert not verify_inclusion_proof_locally(proof, root, sibling)


IDS = {
    "tenant_id": "64527dd3-a654-4410-9327-e58a1492ce77",
    "store_id": "91def158-819a-4461-b5c9-7759750ad157",
    "event_id": "861910c9-7a1d-4b6f-83d6-51bbf4ae2849",
    "agent_id": "80441726-74e2-430a-95ae-97ce21c6351b",
    "command_id": "8af726e2-40e9-4cb6-b7d0-ea463765a9a7",
}
KEY = bytes([7]) * 32


def options(**extra):
    return {
        "tenant_id": IDS["tenant_id"],
        "store_id": IDS["store_id"],
        "agent_id": IDS["agent_id"],
        "private_key": KEY,
        "max_retries": 0,
        **extra,
    }


def test_v2_execution_control_vector_and_mutations():
    identity = "11111111-1111-4111-8111-111111111111"
    params = {
        "ves_version": 2,
        "tenant_id": identity,
        "store_id": identity,
        "event_id": identity,
        "source_agent_id": identity,
        "agent_key_id": 1,
        "entity_type": "order",
        "entity_id": "o1",
        "event_type": "order.created",
        "created_at": "2026-09-05T00:00:00Z",
        "payload_kind": 0,
        "payload_plain_hash": bytes(32),
        "payload_cipher_hash": bytes(32),
        "command_id": identity,
        "base_version": 0,
    }
    original = compute_event_signing_hash(**params)
    assert (
        original.hex()
        == "27dee9ebd0747eafc2b08121f144343627dfe1829a06f818eb23f0c50e048cc5"
    )
    for change in [
        {"base_version": None},
        {"base_version": 1},
        {"command_id": None},
        {"ves_version": 1},
    ]:
        assert compute_event_signing_hash(**(params | change)) != original
    with pytest.raises(ValueError, match="safe integer"):
        compute_event_signing_hash(**(params | {"base_version": 2**53}))


def test_signing_hash_matches_rust_and_node_vector():
    digest = compute_event_signing_hash(
        ves_version=1,
        tenant_id=IDS["tenant_id"],
        store_id=IDS["store_id"],
        event_id=IDS["event_id"],
        source_agent_id=IDS["agent_id"],
        agent_key_id=1,
        entity_type="order",
        entity_id="ORD-001",
        event_type="order.created",
        created_at="2025-12-20T17:51:10.243Z",
        payload_kind=0,
        payload_plain_hash=bytes.fromhex(
            "7777c3fef466a0e9df7e07ea4ff13dc8ffbb9e487098f1b65530cdce7b6bbbe7"
        ),
        payload_cipher_hash=bytes(32),
    )
    assert (
        digest.hex()
        == "e970dfc9ffc285c2c0ba59be5d9c653eee2d1ae4db9b7a02ea3cd62b8e7cf92b"
    )


def test_canonical_payload_is_order_independent():
    first = {"z": [3, {"b": True, "a": None}], "a": "value"}
    second = {"a": "value", "z": [3, {"a": None, "b": True}]}
    assert canonicalize_json(first) == canonicalize_json(second)
    assert compute_payload_plain_hash(first) == compute_payload_plain_hash(second)
    assert (
        compute_payload_plain_hash(
            {"approved": True, "amount": 12.5, "note": "caf\u00e9"}
        ).hex()
        == "89e1d898d457b0706a7313f80f856f17d5f048c64b49c672a5bbffe2e7bb0e43"
    )


def test_record_action_signs_and_authenticates_ingest():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        submitted = json.loads(request.content)["events"][0]
        return httpx.Response(
            200,
            json={
                "receipts": [{"eventId": submitted["event_id"], "sequenceNumber": 42}]
            },
        )

    http = httpx.Client(
        base_url="https://sequencer.example", transport=httpx.MockTransport(handler)
    )
    client = SequencerClient(
        **options(
            base_url="https://sequencer.example", api_key="secret", http_client=http
        )
    )
    result = client.record_action(
        entity_type="order",
        entity_id="ORD-001",
        event_type="order.confirmed",
        payload={"approved": True},
        event_id=IDS["event_id"],
        command_id=IDS["command_id"],
        created_at="2026-09-04T12:00:00.000Z",
        base_version=1,
    )
    event = result["event"]
    signing_hash = compute_event_signing_hash(
        ves_version=event["ves_version"],
        command_id=event.get("command_id"),
        base_version=event.get("base_version"),
        tenant_id=IDS["tenant_id"],
        store_id=IDS["store_id"],
        event_id=IDS["event_id"],
        source_agent_id=IDS["agent_id"],
        agent_key_id=1,
        entity_type=event["entity_type"],
        entity_id=event["entity_id"],
        event_type=event["event_type"],
        created_at=event["created_at"],
        payload_kind=0,
        payload_plain_hash=bytes.fromhex(event["payload_plain_hash"][2:]),
        payload_cipher_hash=bytes(32),
    )
    Ed25519PrivateKey.from_private_bytes(KEY).public_key().verify(
        bytes.fromhex(event["agent_signature"][2:]), signing_hash
    )
    assert result["receipt"]["sequenceNumber"] == 42
    assert requests[0].headers["authorization"] == "ApiKey secret"


@pytest.mark.asyncio
async def test_async_client_reads_projection():
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["source"] == "ves"
        return httpx.Response(200, json={"document": {"status": "confirmed"}})

    http = httpx.AsyncClient(
        base_url="https://sequencer.example", transport=httpx.MockTransport(handler)
    )
    client = AsyncSequencerClient(
        **options(base_url="https://sequencer.example", http_client=http)
    )
    assert await client.get_projection("order", "O/1") == {
        "document": {"status": "confirmed"}
    }
    await http.aclose()


def test_tool_executor_is_read_only_by_default():
    client = object()
    execute = create_tool_executor(client)  # type: ignore[arg-type]
    with pytest.raises(PermissionError, match="writes are disabled"):
        execute(
            "stateset_record_action",
            {
                "entityType": "order",
                "entityId": "O-1",
                "eventType": "order.cancelled",
                "payload": {},
                "commandId": IDS["command_id"],
            },
        )


def test_tool_executor_rejects_malformed_model_arguments():
    execute = create_tool_executor(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unexpected tool arguments"):
        execute("stateset_get_head", {"injected": True})
    with pytest.raises(ValueError, match="payload must be a JSON object"):
        execute(
            "stateset_record_action",
            {
                "entityType": "order",
                "entityId": "O-1",
                "eventType": "order.created",
                "payload": [],
                "commandId": IDS["command_id"],
            },
        )


def test_retry_preserves_the_exact_signed_event():
    bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content)
        if len(bodies) == 1:
            return httpx.Response(503, json={"message": "try again"})
        return httpx.Response(200, json={"receipts": [{"sequenceNumber": 7}]})

    http = httpx.Client(
        base_url="https://sequencer.example", transport=httpx.MockTransport(handler)
    )
    client = SequencerClient(
        **{
            **options(base_url="https://sequencer.example", http_client=http),
            "max_retries": 1,
        }
    )
    client.record_action(
        entity_type="order",
        entity_id="O-1",
        event_type="order.created",
        payload={},
        command_id=IDS["command_id"],
    )
    assert len(bodies) == 2
    assert bodies[0] == bodies[1]


def test_api_errors_retain_structured_context():
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={"message": "denied", "code": "POLICY_DENIED"},
            headers={"x-request-id": "req-1"},
        )

    http = httpx.Client(
        base_url="https://sequencer.example", transport=httpx.MockTransport(handler)
    )
    client = SequencerClient(
        **options(base_url="https://sequencer.example", http_client=http)
    )
    with pytest.raises(SequencerApiError) as captured:
        client.get_head()
    assert captured.value.status == 403
    assert captured.value.code == "POLICY_DENIED"
    assert captured.value.request_id == "req-1"


def test_invalid_configuration_and_sequences_fail_before_network_access():
    with pytest.raises(ValueError, match="either api_key or bearer_token"):
        SequencerClient(**options(api_key="one", bearer_token="two"))
    client = SequencerClient(**options())
    with pytest.raises(ValueError, match="non-negative integer"):
        client.acknowledge(-1)
    with pytest.raises(ValueError, match="agent_id must be a UUID"):
        client.get_agent_policy("not-a-uuid")
    client.close()


@pytest.mark.asyncio
async def test_async_tool_executor_defaults_to_read_only():
    execute = create_async_tool_executor(object())  # type: ignore[arg-type]
    with pytest.raises(PermissionError, match="writes are disabled"):
        await execute(
            "stateset_record_action",
            {
                "entityType": "order",
                "entityId": "O-1",
                "eventType": "order.cancelled",
                "payload": {},
                "commandId": IDS["command_id"],
            },
        )
