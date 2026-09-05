"""Signed VES clients for StateSet Sequencer."""

from __future__ import annotations

import asyncio
import hashlib
import os
import struct
import sys
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any, cast
from urllib.parse import quote

import httpx
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

JsonObject = dict[str, Any]
Predicate = Callable[[JsonObject], bool]
AsyncPredicate = Callable[[JsonObject], bool | Awaitable[bool]]

_PAYLOAD_DOMAIN = b"VES_PAYLOAD_PLAIN_V1"
_SIGNATURE_DOMAIN = b"VES_EVENTSIG_V1"
_ZERO_HASH = bytes(32)
_RETRYABLE_STATUSES = {408, 425, 429}


class SequencerApiError(Exception):
    """A structured transport or API error returned by the sequencer."""

    def __init__(
        self,
        message: str,
        *,
        status: int = 0,
        code: str | None = None,
        request_id: str | None = None,
        retry_after: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.request_id = request_id
        self.retry_after = retry_after


def canonicalize_json(value: Any) -> bytes:
    """Serialize a JSON-domain value according to RFC 8785/JCS."""

    return rfc8785.dumps(value)


def compute_payload_plain_hash(payload: Any) -> bytes:
    return hashlib.sha256(_PAYLOAD_DOMAIN + canonicalize_json(payload)).digest()


def verify_inclusion_proof_locally(
    proof: Mapping[str, Any], expected_root: str, expected_leaf: str
) -> bool:
    """Verify membership offline against independently trusted root/leaf hashes."""

    def decode(value: Any) -> bytes:
        if not isinstance(value, str):
            raise TypeError("Expected a hexadecimal hash")
        raw = value.removeprefix("0x")
        if len(raw) != 64 or any(c not in "0123456789abcdefABCDEF" for c in raw):
            raise ValueError("Expected a 32-byte hexadecimal hash")
        return bytes.fromhex(raw)

    try:
        root, current = decode(expected_root), decode(expected_leaf)
        if (
            decode(proof["merkle_root"]) != root
            or decode(proof["leaf_hash"]) != current
        ):
            return False
        path, directions, index = (
            proof["proof_path"],
            proof["directions"],
            proof["leaf_index"],
        )
        if (
            type(index) is not int
            or index < 0
            or index > 2**53 - 1
            or not isinstance(path, list)
            or len(path) > 64
            or not isinstance(directions, list)
            or len(directions) != len(path)
        ):
            return False
        for sibling_hash, direction in zip(path, directions):
            left = index % 2 == 0
            if type(direction) is not bool or direction != left:
                return False
            sibling = decode(sibling_hash)
            children = current + sibling if left else sibling + current
            current = hashlib.sha256(b"VES_NODE_V1" + children).digest()
            index //= 2
        return index == 0 and current == root
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def compute_event_signing_hash(
    *,
    ves_version: int,
    tenant_id: str,
    store_id: str,
    event_id: str,
    source_agent_id: str,
    agent_key_id: int,
    entity_type: str,
    entity_id: str,
    event_type: str,
    created_at: str,
    payload_kind: int,
    payload_plain_hash: bytes,
    payload_cipher_hash: bytes,
    command_id: str | None = None,
    base_version: int | None = None,
) -> bytes:
    """Compute the domain-separated hash signed by a VES agent."""

    if ves_version not in (1, 2):
        raise ValueError("Unsupported signing version")
    body = b"".join(
        (
            _SIGNATURE_DOMAIN,
            _u32(ves_version),
            uuid.UUID(tenant_id).bytes,
            uuid.UUID(store_id).bytes,
            uuid.UUID(event_id).bytes,
            uuid.UUID(source_agent_id).bytes,
            _u32(agent_key_id),
            _encoded_string(entity_type),
            _encoded_string(entity_id),
            _encoded_string(event_type),
            _encoded_string(created_at),
            _u32(payload_kind),
            _hash_bytes(payload_plain_hash, "payload_plain_hash"),
            _hash_bytes(payload_cipher_hash, "payload_cipher_hash"),
        )
    )
    event_hash = hashlib.sha256(body).digest()
    if ves_version == 1:
        return event_hash
    if base_version is not None and (
        type(base_version) is not int or not 0 <= base_version <= 2**53 - 1
    ):
        raise ValueError("base_version must be a non-negative safe integer")
    command = b"\x00" if command_id is None else b"\x01" + uuid.UUID(command_id).bytes
    base = (
        b"\x00" if base_version is None else b"\x01" + struct.pack(">Q", base_version)
    )
    return hashlib.sha256(b"VES_EVENTSIG_V2" + event_hash + command + base).digest()


def load_private_key(env_var: str = "VES_PRIVATE_KEY") -> bytes:
    value = os.getenv(env_var)
    if not value:
        raise RuntimeError(f"{env_var} environment variable not set")
    try:
        key = bytes.fromhex(value.removeprefix("0x"))
    except ValueError as error:
        raise ValueError(f"{env_var} must be hexadecimal") from error
    if len(key) != 32:
        raise ValueError(f"{env_var} must contain a 32-byte Ed25519 key")
    return key


class _ClientBase:
    def __init__(
        self,
        *,
        tenant_id: str,
        store_id: str,
        agent_id: str,
        private_key: bytes,
        base_url: str = "http://localhost:8080",
        key_id: int = 1,
        signing_version: int = 2,
        api_key: str | None = None,
        bearer_token: str | None = None,
        max_retries: int = 3,
        timeout: float = 30.0,
    ) -> None:
        self.tenant_id = str(uuid.UUID(tenant_id))
        self.store_id = str(uuid.UUID(store_id))
        self.agent_id = str(uuid.UUID(agent_id))
        if not 0 <= key_id <= 0xFFFFFFFF:
            raise ValueError("key_id must be an unsigned 32-bit integer")
        if len(private_key) != 32:
            raise ValueError("private_key must contain exactly 32 bytes")
        if api_key and bearer_token:
            raise ValueError("configure either api_key or bearer_token, not both")
        if max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        self.base_url = base_url.rstrip("/")
        self.key_id = key_id
        if signing_version not in (1, 2):
            raise ValueError("Unsupported signing version")
        self.signing_version = signing_version
        self._signing_key = Ed25519PrivateKey.from_private_bytes(private_key)
        self.api_key = api_key
        self.bearer_token = bearer_token
        self.max_retries = max_retries
        self.timeout = timeout

    def create_event(
        self,
        *,
        entity_type: str,
        entity_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        command_id: str | None = None,
        base_version: int | None = None,
        event_id: str | None = None,
        created_at: str | None = None,
    ) -> JsonObject:
        event_id = str(uuid.UUID(event_id)) if event_id else str(uuid.uuid4())
        created_at = created_at or _utc_now()
        payload_hash = compute_payload_plain_hash(payload)
        signing_hash = compute_event_signing_hash(
            ves_version=self.signing_version,
            command_id=command_id,
            base_version=base_version,
            tenant_id=self.tenant_id,
            store_id=self.store_id,
            event_id=event_id,
            source_agent_id=self.agent_id,
            agent_key_id=self.key_id,
            entity_type=entity_type,
            entity_id=entity_id,
            event_type=event_type,
            created_at=created_at,
            payload_kind=0,
            payload_plain_hash=payload_hash,
            payload_cipher_hash=_ZERO_HASH,
        )
        event: JsonObject = {
            "ves_version": self.signing_version,
            "event_id": event_id,
            "tenant_id": self.tenant_id,
            "store_id": self.store_id,
            "source_agent_id": self.agent_id,
            "agent_key_id": self.key_id,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "event_type": event_type,
            "created_at": created_at,
            "payload_kind": 0,
            "payload": dict(payload),
            "payload_plain_hash": "0x" + payload_hash.hex(),
            "payload_cipher_hash": "0x" + _ZERO_HASH.hex(),
            "agent_signature": "0x" + self._signing_key.sign(signing_hash).hex(),
        }
        if command_id is not None:
            event["command_id"] = str(uuid.UUID(command_id))
        if base_version is not None:
            if base_version < 0:
                raise ValueError("base_version must be non-negative")
            event["base_version"] = base_version
        return event

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        elif self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        return headers

    def _scope(self) -> dict[str, str]:
        return {"tenant_id": self.tenant_id, "store_id": self.store_id}


class SequencerClient(_ClientBase):
    """Synchronous signed VES client. Safe to use as a context manager."""

    def __init__(
        self, *, http_client: httpx.Client | None = None, **options: Any
    ) -> None:
        super().__init__(**options)
        self._owns_client = http_client is None
        self._http = http_client or httpx.Client(
            base_url=self.base_url, timeout=self.timeout
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self._http.close()

    def ingest(self, events: Sequence[Mapping[str, Any]]) -> JsonObject:
        if not events:
            raise ValueError("events must be non-empty")
        return self._request(
            "POST",
            "/api/v1/ves/events/ingest",
            json={"agentId": self.agent_id, "events": list(events)},
            retryable=True,
        )

    def record_action(self, **event: Any) -> JsonObject:
        envelope = self.create_event(**event)
        result = self.ingest([envelope])
        _raise_rejection(result, envelope["event_id"])
        receipts = result.get("receipts") or []
        return {
            "event": envelope,
            "receipt": receipts[0] if receipts else None,
            "result": result,
        }

    def get_head(self) -> JsonObject:
        return self._request("GET", "/api/v1/ves/head", params=self._scope())

    def list_events(self, *, from_sequence: int = 1, limit: int = 100) -> JsonObject:
        return self._request(
            "GET",
            "/api/v1/ves/events",
            params={**self._scope(), "from": from_sequence, "limit": limit},
        )

    def get_entity_history(
        self,
        entity_type: str,
        entity_id: str,
        *,
        from_sequence: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        path = f"/api/v1/ves/entities/{quote(entity_type, safe='')}/{quote(entity_id, safe='')}"
        return self._request(
            "GET", path, params={**self._scope(), "from": from_sequence, "limit": limit}
        )

    def get_projection(
        self, entity_type: str, entity_id: str, *, source: str = "ves"
    ) -> JsonObject:
        _validate_source(source)
        path = f"/api/v1/projections/{quote(entity_type, safe='')}/{quote(entity_id, safe='')}"
        return self._request("GET", path, params={**self._scope(), "source": source})

    def get_inclusion_proof(self, sequence_number: int) -> JsonObject:
        _validate_sequence(sequence_number)
        return self._request(
            "GET", f"/api/v1/ves/proofs/{sequence_number}", params=self._scope()
        )

    def verify_inclusion_proof(self, proof: Mapping[str, Any]) -> JsonObject:
        return self._request("POST", "/api/v1/ves/proofs/verify", json=dict(proof))

    def get_cursor(self) -> JsonObject:
        return self._request(
            "GET", f"/api/v1/ves/cursors/{self.agent_id}", params=self._scope()
        )

    def acknowledge(self, sequence_number: int) -> JsonObject:
        _validate_sequence(sequence_number)
        return self._request(
            "PUT",
            f"/api/v1/ves/cursors/{self.agent_id}",
            json={
                "tenantId": self.tenant_id,
                "storeId": self.store_id,
                "sequenceNumber": sequence_number,
            },
            retryable=True,
        )

    def get_agent_policy(self, agent_id: str | None = None) -> JsonObject:
        return self._request(
            "GET",
            f"/api/v1/agents/{_agent_id(agent_id or self.agent_id)}/policy",
            params={"tenant_id": self.tenant_id},
        )

    def set_agent_policy(
        self, policy: Mapping[str, Any], agent_id: str | None = None
    ) -> JsonObject:
        return self._request(
            "PUT",
            f"/api/v1/agents/{_agent_id(agent_id or self.agent_id)}/policy",
            json={**policy, "tenantId": self.tenant_id},
            retryable=True,
        )

    def wait_for_event(
        self,
        predicate: Predicate,
        *,
        from_sequence: int = 1,
        limit: int = 100,
        poll_interval: float = 1.0,
        timeout: float = 60.0,
    ) -> JsonObject:
        cursor, deadline = from_sequence, time.monotonic() + timeout
        while time.monotonic() < deadline:
            page = self.list_events(from_sequence=cursor, limit=limit)
            events = _events_from_page(page)
            for event in events:
                if predicate(event):
                    return event
            cursor = _next_cursor(page, events, cursor)
            time.sleep(min(poll_interval, max(0.0, deadline - time.monotonic())))
        raise SequencerApiError(
            "Timed out waiting for a matching event", code="TIMEOUT"
        )

    def _request(
        self, method: str, path: str, *, retryable: bool = False, **kwargs: Any
    ) -> JsonObject:
        attempts = self.max_retries + 1 if retryable or method == "GET" else 1
        for attempt in range(attempts):
            try:
                response = self._http.request(
                    method,
                    path,
                    headers=self._headers(),
                    timeout=self.timeout,
                    **kwargs,
                )
                if response.is_success:
                    return cast(JsonObject, _response_json(response))
                error = _api_error(response)
                if not _retryable(response.status_code) or attempt + 1 == attempts:
                    raise error
            except (httpx.TransportError, httpx.TimeoutException) as error:
                if attempt + 1 == attempts:
                    raise SequencerApiError("Sequencer request failed") from error
            time.sleep(min(0.25 * (2**attempt), 2.0))
        raise AssertionError("unreachable")


class AsyncSequencerClient(_ClientBase):
    """Asynchronous signed VES client. Safe to use with ``async with``."""

    def __init__(
        self, *, http_client: httpx.AsyncClient | None = None, **options: Any
    ) -> None:
        super().__init__(**options)
        self._owns_client = http_client is None
        self._http = http_client or httpx.AsyncClient(
            base_url=self.base_url, timeout=self.timeout
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def close(self) -> None:
        if self._owns_client:
            await self._http.aclose()

    async def ingest(self, events: Sequence[Mapping[str, Any]]) -> JsonObject:
        if not events:
            raise ValueError("events must be non-empty")
        return await self._request(
            "POST",
            "/api/v1/ves/events/ingest",
            json={"agentId": self.agent_id, "events": list(events)},
            retryable=True,
        )

    async def record_action(self, **event: Any) -> JsonObject:
        envelope = self.create_event(**event)
        result = await self.ingest([envelope])
        _raise_rejection(result, envelope["event_id"])
        receipts = result.get("receipts") or []
        return {
            "event": envelope,
            "receipt": receipts[0] if receipts else None,
            "result": result,
        }

    async def get_head(self) -> JsonObject:
        return await self._request("GET", "/api/v1/ves/head", params=self._scope())

    async def list_events(
        self, *, from_sequence: int = 1, limit: int = 100
    ) -> JsonObject:
        return await self._request(
            "GET",
            "/api/v1/ves/events",
            params={**self._scope(), "from": from_sequence, "limit": limit},
        )

    async def get_entity_history(
        self,
        entity_type: str,
        entity_id: str,
        *,
        from_sequence: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        path = f"/api/v1/ves/entities/{quote(entity_type, safe='')}/{quote(entity_id, safe='')}"
        return await self._request(
            "GET", path, params={**self._scope(), "from": from_sequence, "limit": limit}
        )

    async def get_projection(
        self, entity_type: str, entity_id: str, *, source: str = "ves"
    ) -> JsonObject:
        _validate_source(source)
        path = f"/api/v1/projections/{quote(entity_type, safe='')}/{quote(entity_id, safe='')}"
        return await self._request(
            "GET", path, params={**self._scope(), "source": source}
        )

    async def get_inclusion_proof(self, sequence_number: int) -> JsonObject:
        _validate_sequence(sequence_number)
        return await self._request(
            "GET", f"/api/v1/ves/proofs/{sequence_number}", params=self._scope()
        )

    async def verify_inclusion_proof(self, proof: Mapping[str, Any]) -> JsonObject:
        return await self._request(
            "POST", "/api/v1/ves/proofs/verify", json=dict(proof)
        )

    async def get_cursor(self) -> JsonObject:
        return await self._request(
            "GET", f"/api/v1/ves/cursors/{self.agent_id}", params=self._scope()
        )

    async def acknowledge(self, sequence_number: int) -> JsonObject:
        _validate_sequence(sequence_number)
        return await self._request(
            "PUT",
            f"/api/v1/ves/cursors/{self.agent_id}",
            json={
                "tenantId": self.tenant_id,
                "storeId": self.store_id,
                "sequenceNumber": sequence_number,
            },
            retryable=True,
        )

    async def get_agent_policy(self, agent_id: str | None = None) -> JsonObject:
        return await self._request(
            "GET",
            f"/api/v1/agents/{_agent_id(agent_id or self.agent_id)}/policy",
            params={"tenant_id": self.tenant_id},
        )

    async def set_agent_policy(
        self, policy: Mapping[str, Any], agent_id: str | None = None
    ) -> JsonObject:
        return await self._request(
            "PUT",
            f"/api/v1/agents/{_agent_id(agent_id or self.agent_id)}/policy",
            json={**policy, "tenantId": self.tenant_id},
            retryable=True,
        )

    async def wait_for_event(
        self,
        predicate: AsyncPredicate,
        *,
        from_sequence: int = 1,
        limit: int = 100,
        poll_interval: float = 1.0,
        timeout: float = 60.0,
    ) -> JsonObject:
        cursor = from_sequence
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            page = await self.list_events(from_sequence=cursor, limit=limit)
            events = _events_from_page(page)
            for event in events:
                matched = predicate(event)
                if asyncio.iscoroutine(matched):
                    matched = await matched
                if matched:
                    return event
            cursor = _next_cursor(page, events, cursor)
            await asyncio.sleep(min(poll_interval, max(0.0, deadline - loop.time())))
        raise SequencerApiError(
            "Timed out waiting for a matching event", code="TIMEOUT"
        )

    async def _request(
        self, method: str, path: str, *, retryable: bool = False, **kwargs: Any
    ) -> JsonObject:
        attempts = self.max_retries + 1 if retryable or method == "GET" else 1
        for attempt in range(attempts):
            try:
                response = await self._http.request(
                    method,
                    path,
                    headers=self._headers(),
                    timeout=self.timeout,
                    **kwargs,
                )
                if response.is_success:
                    return cast(JsonObject, _response_json(response))
                error = _api_error(response)
                if not _retryable(response.status_code) or attempt + 1 == attempts:
                    raise error
            except (httpx.TransportError, httpx.TimeoutException) as error:
                if attempt + 1 == attempts:
                    raise SequencerApiError("Sequencer request failed") from error
            await asyncio.sleep(min(0.25 * (2**attempt), 2.0))
        raise AssertionError("unreachable")


def _u32(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("expected an unsigned 32-bit integer")
    return struct.pack(">I", value)


def _encoded_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return _u32(len(encoded)) + encoded


def _hash_bytes(value: bytes, name: str) -> bytes:
    if len(value) != 32:
        raise ValueError(f"{name} must contain exactly 32 bytes")
    return value


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _validate_source(source: str) -> None:
    if source not in {"ves", "legacy"}:
        raise ValueError('source must be "ves" or "legacy"')


def _validate_sequence(sequence_number: int) -> None:
    if (
        not isinstance(sequence_number, int)
        or isinstance(sequence_number, bool)
        or sequence_number < 0
    ):
        raise ValueError("sequence_number must be a non-negative integer")


def _agent_id(value: str) -> str:
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError) as error:
        raise ValueError("agent_id must be a UUID") from error


def _retryable(status: int) -> bool:
    return status in _RETRYABLE_STATUSES or status >= 500


def _response_json(response: httpx.Response) -> Any:
    if response.status_code == 204 or not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        return {"message": response.text}


def _api_error(response: httpx.Response) -> SequencerApiError:
    body = _response_json(response) or {}
    message = (
        body.get("message")
        or body.get("error")
        or f"Sequencer request failed with {response.status_code}"
    )
    return SequencerApiError(
        message,
        status=response.status_code,
        code=body.get("code"),
        request_id=response.headers.get("x-request-id"),
        retry_after=response.headers.get("retry-after"),
    )


def _raise_rejection(result: JsonObject, event_id: str) -> None:
    for rejection in result.get("rejections") or []:
        if rejection.get("event_id", rejection.get("eventId")) == event_id:
            raise SequencerApiError(
                rejection.get("message", "Event rejected"), code=rejection.get("reason")
            )


def _next_cursor(page: Any, events: Sequence[JsonObject], fallback: int) -> int:
    if isinstance(page, dict):
        explicit = page.get("next_sequence", page.get("nextSequence"))
        if explicit is not None:
            return int(str(explicit))
    if not events:
        return fallback
    last = events[-1]
    return (
        int(str(last.get("sequence_number", last.get("sequenceNumber", fallback)))) + 1
    )


def _events_from_page(page: Any) -> list[JsonObject]:
    value = page.get("events", []) if isinstance(page, dict) else page
    if not isinstance(value, list) or not all(
        isinstance(event, dict) for event in value
    ):
        raise SequencerApiError(
            "Sequencer returned an invalid event page", code="INVALID_RESPONSE"
        )
    return cast(list[JsonObject], value)
