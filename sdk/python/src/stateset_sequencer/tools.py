"""OpenAI-compatible tool definitions backed by a sequencer client."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from typing import Any

from .client import AsyncSequencerClient, SequencerClient, canonicalize_json

SEQUENCER_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "stateset_get_head",
            "description": "Get the authoritative latest sequence for the configured tenant and store.",
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "stateset_get_entity_history",
            "description": "Read the authoritative ordered history for a commerce entity.",
            "parameters": {
                "type": "object",
                "required": ["entityType", "entityId"],
                "properties": {
                    "entityType": {"type": "string"},
                    "entityId": {"type": "string"},
                    "from": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "stateset_get_projection",
            "description": "Read the latest durable materialized state for a commerce entity.",
            "parameters": {
                "type": "object",
                "required": ["entityType", "entityId"],
                "properties": {
                    "entityType": {"type": "string"},
                    "entityId": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "stateset_record_action",
            "description": "Sign and append an idempotent action to the authoritative event stream.",
            "parameters": {
                "type": "object",
                "required": [
                    "entityType",
                    "entityId",
                    "eventType",
                    "payload",
                    "commandId",
                ],
                "properties": {
                    "entityType": {"type": "string"},
                    "entityId": {"type": "string"},
                    "eventType": {"type": "string"},
                    "payload": {"type": "object"},
                    "commandId": {"type": "string", "format": "uuid"},
                    "baseVersion": {"type": "integer", "minimum": 0},
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "stateset_get_inclusion_proof",
            "description": "Get cryptographic proof that a sequence is included in a committed batch.",
            "parameters": {
                "type": "object",
                "required": ["sequenceNumber"],
                "properties": {"sequenceNumber": {"type": "integer", "minimum": 1}},
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "stateset_get_cursor",
            "description": "Read this agent's durable acknowledged sequence and stream lag.",
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "stateset_acknowledge",
            "description": "Persist the highest sequence this agent has durably processed.",
            "parameters": {
                "type": "object",
                "required": ["sequenceNumber"],
                "properties": {"sequenceNumber": {"type": "integer", "minimum": 0}},
                "additionalProperties": False,
            },
        },
    },
]


def create_tool_executor(
    client: SequencerClient,
    *,
    allowed_event_types: set[str] | None = None,
    allowed_entity_types: set[str] | None = None,
    require_base_version: bool = False,
    max_payload_bytes: int | None = None,
    validate_action: Callable[[Mapping[str, Any]], None] | None = None,
) -> Callable[[str, Mapping[str, Any]], Any]:
    """Create a policy-constrained function-tool executor."""

    def execute(name: str, arguments: Mapping[str, Any]) -> Any:
        args = dict(arguments)
        _validate_tool_arguments(name, args)
        if name == "stateset_get_head":
            return client.get_head()
        if name == "stateset_get_entity_history":
            return client.get_entity_history(
                args["entityType"],
                args["entityId"],
                from_sequence=args.get("from", 0),
                limit=args.get("limit", 100),
            )
        if name == "stateset_get_projection":
            return client.get_projection(args["entityType"], args["entityId"])
        if name == "stateset_get_inclusion_proof":
            return client.get_inclusion_proof(args["sequenceNumber"])
        if name == "stateset_get_cursor":
            return client.get_cursor()
        if name == "stateset_acknowledge":
            return client.acknowledge(args["sequenceNumber"])
        if name == "stateset_record_action":
            _authorize_action(
                args,
                allowed_event_types=allowed_event_types,
                allowed_entity_types=allowed_entity_types,
                require_base_version=require_base_version,
                max_payload_bytes=max_payload_bytes,
            )
            if validate_action:
                validate_action(args)
            return client.record_action(
                entity_type=args["entityType"],
                entity_id=args["entityId"],
                event_type=args["eventType"],
                payload=args["payload"],
                command_id=args["commandId"],
                base_version=args.get("baseVersion"),
            )
        raise ValueError(f"unknown StateSet tool: {name}")

    return execute


def create_async_tool_executor(
    client: AsyncSequencerClient,
    *,
    allowed_event_types: set[str] | None = None,
    allowed_entity_types: set[str] | None = None,
    require_base_version: bool = False,
    max_payload_bytes: int | None = None,
    validate_action: Callable[[Mapping[str, Any]], None] | None = None,
) -> Callable[[str, Mapping[str, Any]], Any]:
    """Create the asynchronous equivalent of :func:`create_tool_executor`."""

    async def execute(name: str, arguments: Mapping[str, Any]) -> Any:
        args = dict(arguments)
        _validate_tool_arguments(name, args)
        if name == "stateset_get_head":
            return await client.get_head()
        if name == "stateset_get_entity_history":
            return await client.get_entity_history(
                args["entityType"],
                args["entityId"],
                from_sequence=args.get("from", 0),
                limit=args.get("limit", 100),
            )
        if name == "stateset_get_projection":
            return await client.get_projection(args["entityType"], args["entityId"])
        if name == "stateset_get_inclusion_proof":
            return await client.get_inclusion_proof(args["sequenceNumber"])
        if name == "stateset_get_cursor":
            return await client.get_cursor()
        if name == "stateset_acknowledge":
            return await client.acknowledge(args["sequenceNumber"])
        if name == "stateset_record_action":
            _authorize_action(
                args,
                allowed_event_types=allowed_event_types,
                allowed_entity_types=allowed_entity_types,
                require_base_version=require_base_version,
                max_payload_bytes=max_payload_bytes,
            )
            if validate_action:
                validate_action(args)
            return await client.record_action(
                entity_type=args["entityType"],
                entity_id=args["entityId"],
                event_type=args["eventType"],
                payload=args["payload"],
                command_id=args["commandId"],
                base_version=args.get("baseVersion"),
            )
        raise ValueError(f"unknown StateSet tool: {name}")

    return execute


_ARGUMENTS: dict[str, tuple[set[str], set[str]]] = {
    "stateset_get_head": (set(), set()),
    "stateset_get_entity_history": (
        {"entityType", "entityId"},
        {"entityType", "entityId", "from", "limit"},
    ),
    "stateset_get_projection": (
        {"entityType", "entityId"},
        {"entityType", "entityId"},
    ),
    "stateset_record_action": (
        {"entityType", "entityId", "eventType", "payload", "commandId"},
        {
            "entityType",
            "entityId",
            "eventType",
            "payload",
            "commandId",
            "baseVersion",
        },
    ),
    "stateset_get_inclusion_proof": ({"sequenceNumber"}, {"sequenceNumber"}),
    "stateset_get_cursor": (set(), set()),
    "stateset_acknowledge": ({"sequenceNumber"}, {"sequenceNumber"}),
}


def _validate_tool_arguments(name: str, args: dict[str, Any]) -> None:
    if name not in _ARGUMENTS:
        raise ValueError(f"unknown StateSet tool: {name}")
    required, allowed = _ARGUMENTS[name]
    missing = required - args.keys()
    unexpected = args.keys() - allowed
    if missing:
        raise ValueError(f"missing tool arguments: {', '.join(sorted(missing))}")
    if unexpected:
        raise ValueError(f"unexpected tool arguments: {', '.join(sorted(unexpected))}")
    for field, string_maximum in (
        ("entityType", 128),
        ("entityId", 512),
        ("eventType", 128),
    ):
        if field in args and (
            not isinstance(args[field], str)
            or not args[field]
            or len(args[field]) > string_maximum
        ):
            raise ValueError(
                f"{field} must be a non-empty string of at most {string_maximum} characters"
            )
    for field, minimum, integer_maximum in (
        ("from", 0, None),
        ("limit", 1, 100),
        ("baseVersion", 0, None),
        ("sequenceNumber", 0, None),
    ):
        if field in args:
            value = args[field]
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < minimum
                or (integer_maximum is not None and value > integer_maximum)
            ):
                raise ValueError(f"{field} is outside its allowed integer range")
    if "payload" in args and not isinstance(args["payload"], dict):
        raise ValueError("payload must be a JSON object")
    if name == "stateset_get_inclusion_proof" and args["sequenceNumber"] < 1:
        raise ValueError("sequenceNumber must be at least 1")
    if "commandId" in args:
        try:
            args["commandId"] = str(uuid.UUID(args["commandId"]))
        except (ValueError, AttributeError) as error:
            raise ValueError("commandId must be a UUID") from error


def _authorize_action(
    args: dict[str, Any],
    *,
    allowed_event_types: set[str] | None,
    allowed_entity_types: set[str] | None,
    require_base_version: bool,
    max_payload_bytes: int | None,
) -> None:
    if allowed_event_types is None:
        raise PermissionError(
            "writes are disabled until allowed_event_types is configured"
        )
    if not _matches_any(allowed_event_types, args["eventType"]):
        raise PermissionError(f"event type is not allowed: {args['eventType']}")
    if allowed_entity_types is not None and not _matches_any(
        allowed_entity_types, args["entityType"]
    ):
        raise PermissionError(f"entity type is not allowed: {args['entityType']}")
    if (
        require_base_version
        and not args["eventType"].endswith(".created")
        and "baseVersion" not in args
    ):
        raise ValueError("baseVersion is required when modifying an existing entity")
    if (
        max_payload_bytes is not None
        and len(canonicalize_json(args["payload"])) > max_payload_bytes
    ):
        raise ValueError(
            f"payload exceeds this agent's {max_payload_bytes} byte policy limit"
        )


def _matches_any(patterns: set[str], value: str) -> bool:
    return any(
        pattern == value or (pattern.endswith(".*") and value.startswith(pattern[:-1]))
        for pattern in patterns
    )
